/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2022 Nick Kossifidis <mickflemm@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ext4backup.h"
#include <stddef.h>	/* For NULL, offsetof */
#include <stdlib.h>	/* For malloc()/realloc()/free() */
#include <string.h>	/* For memcpy() */
#include <libudev.h>	/* For udev_*() functions and related structs */
#include <sys/ioctl.h>	/* For ioctl() */
#include <linux/fs.h>	/* For FIFREEZE/FITHAW */
#include <fcntl.h>	/* For open(), O_* flags, AT_* flags */
#include <unistd.h>	/* For close(), readlinkat() */
#include <sys/stat.h>	/* For stat(), statx() */
#include <ext2fs/ext2fs.h>	/* For libext2fs structs/functions */
#include <linux/fscrypt.h>


/*********\
* HELPERS *
\*********/

int get_path_info(const char *path, int fd, struct statx *buf, bool may_not_exist)
{
	uint32_t requested_stx_mask =
		STATX_TYPE | STATX_MODE | STATX_UID | STATX_GID | STATX_ATIME |
		STATX_MTIME | STATX_CTIME | STATX_BTIME | STATX_MNT_ID | STATX_INO |
		STATX_SIZE;
	int flags = AT_SYMLINK_NOFOLLOW | AT_STATX_FORCE_SYNC;
	int dirfd = 0;
	int ret = 0;

	if (!path && fd > 2) {
		dirfd = fd;
		path = "";
		flags |= AT_EMPTY_PATH;
	} else if (fd > 2)
		dirfd = fd;

	ret = TEMP_FAILURE_RETRY(statx(dirfd, path, flags, requested_stx_mask, buf));
	if (ret) {
		if (may_not_exist && errno == ENOENT) {
			return errno;
		}
		if (!(flags & AT_EMPTY_PATH))
			utils_err("Error while getting information for:\n\t%s\n", path);
		utils_perr("statx() failed");
		return errno;
	}

	/* Mask-out unsupported attributes */
	buf->stx_attributes &= buf->stx_attributes_mask;

	if ((buf->stx_mask & requested_stx_mask) != requested_stx_mask) {
		/* No worries if we didn't get BTIME (crtime), we can recover from it */
		if (((buf->stx_mask & requested_stx_mask) ^ requested_stx_mask) == STATX_BTIME)
			return 0;
		utils_err("Kernel didn't return all requested infos on statx:\n\t(0x%X vs 0x%X)\n",
			  (buf->stx_mask & requested_stx_mask), requested_stx_mask);
		return EIO;
	}

	return 0;
}

char *get_lnk_path(struct e4b_entry *entry, struct e4b_state *st, int dst, int *pathlen)
{
	char *lnk_path = NULL;
	char *tmp = NULL;
	int lnk_pathlen = 0;
	int tmp_lnk_pathlen = 64;
	int dirfd = dst ? st->dst_dirfd : st->src_dirfd;
retry:
	if (!lnk_path || lnk_pathlen != 0) {
		tmp = realloc(lnk_path, tmp_lnk_pathlen);
		if (!tmp) {
			utils_err("Could not allocate buffer for new symlink target\n");
			if (lnk_path)
				free(lnk_path);
			return NULL;
		} else
			lnk_path = tmp;
	}

	lnk_pathlen = readlinkat(dirfd, entry->path, lnk_path, tmp_lnk_pathlen);
	if (lnk_pathlen < 0) {
		utils_err("Could not get symlink contents for:\n\t%s\n", entry->path);
		utils_perr("readlink() failed");
		free(lnk_path);
		return NULL;
	}

	/* Did readlink truncate ? */
	if (lnk_pathlen == tmp_lnk_pathlen) {
		tmp_lnk_pathlen += 64;
		goto retry;
	}

	lnk_path[lnk_pathlen] = '\0';
	if (pathlen)
		*pathlen = lnk_pathlen;
	return lnk_path;
}

int check_lnk_path_match(struct e4b_entry *entry, struct e4b_state *st)
{
	int src_lnk_pathlen = 0;
	char *src_lnk_path = get_lnk_path(entry, st, 0, &src_lnk_pathlen);
	char *dst_lnk_path = get_lnk_path(entry, st, 1, NULL);
	int ret = 0;

	if (!src_lnk_path | !dst_lnk_path) {
		if (src_lnk_path)
			free(src_lnk_path);
		if (dst_lnk_path)
			free(dst_lnk_path);
		return 0;
	}

	ret = strncmp(src_lnk_path, dst_lnk_path, src_lnk_pathlen);
	free(src_lnk_path);
	free(dst_lnk_path);
	return ret;
}

static int get_mountpoint_len(const char *path_in) {
	struct stat pathinfo = {0};
	char *path = NULL;
	char *last = strrchr(path_in, '/');
	char *prev_last = NULL;
	char saved_last = '\0';
	dev_t this_devid = 0;
	dev_t last_devid = 0;
	int ret = 0;

	if (!last) {
		utils_err("Provided path doesn't include '/'\n");
		return 0;	
	}

	/* Make a copy of path_in to tamper with */
	ret = strnlen(path_in, PATH_MAX);
	path = malloc(ret + 1);
	if (!path) {
		utils_err("Could not allocate buffer for path manipulation\n");
		utils_perr("malloc() failed");
		return 0;
	}
	memcpy(path, path_in, ret + 1);

	while (*path != '\0') {
		ret = stat(path, &pathinfo);
		if (ret) {
			utils_err("Could not stat a path component: %s\n", path);
			utils_perr("stat() failed");
			free(path);
			return 0;
		}
		this_devid = pathinfo.st_dev;
		if (last_devid && this_devid != last_devid) {
			/* Restore '/' before mountpoint */
			*prev_last = saved_last;
			ret = strnlen(path, PATH_MAX);
			utils_dbg("found: %s, len: %i\n", path, ret);
			free(path);
			return ret;
		} else if (last == path) {
			/* We reached root and all components had
			 * the same devid. */
			 free(path);
			 return 0;
		}
		last_devid = this_devid;
		last = strrchr(path, '/');
		if (last != path) {
			prev_last = last;
			saved_last = '/';
			*last = '\0';
		/* Reached root, we need to check against it as well
		 * in case our mountpoint is the first path component
		 * (e.g. /home), so terminate on the character after
		 * '/' instead. */
		} else {
			saved_last = *(last + 1);
			*(last + 1) = '\0';
			prev_last = last + 1;
			last = path;
		}
		utils_dbg("check: %s, this_devid: %i\n", path, this_devid);
	};

	free(path);
	return 0;
}

/******************\
* FSFREEZE/ FSTHAW *
\******************/

int set_fs_freeze(char* path, bool freeze) {
	struct stat pathinfo = {0};
	int mountpoint_len = get_mountpoint_len(path);
	char saved = '\0';
	int mpfd = 0;
	int ret = 0;

	/* Temporarily terminate path at mountpoint_len + 1*/
	saved = path[mountpoint_len];
	path[mountpoint_len] = '\0';

	mpfd = open(path, O_RDONLY);
	if (mpfd < 0) {
		utils_wrn("Could not open mountpoint for %s\n", path);
		path[mountpoint_len] = saved;
		utils_wrn("open() failed: %s\n", strerror(errno));
		return errno;
	}
	
	/* Sanity check: make sure it's a directory */
	ret = stat(path, &pathinfo);
	if (ret) {
		utils_err("Could not get mountpoint info: %s\n", path);
		path[mountpoint_len] = saved;
		utils_perr("stat() failed");
		return errno;
	}
	path[mountpoint_len] = saved;

	if (freeze) {
		ret = ioctl(mpfd, FIFREEZE, 0);	
	} else {
		ret = ioctl(mpfd, FITHAW, 0);
	}

	close(mpfd);
	if (ret)
		return EIO;
	return 0;
}

/***************************************\
* LOW LEVEL EXT4 STUFF FOR CTIME/CRTIME *
\***************************************/

static void xtime_decode(uint32_t xtime, uint32_t xtime_extra, struct timespec *ts)
{
	ts->tv_sec = (signed) xtime;

	if (!xtime_extra)
		return;

	/* Extra bits: (nsec << 2 | epoch) */
	if (sizeof(ts->tv_sec) > sizeof(uint32_t) &&
	    (xtime_extra & EXT4_EPOCH_MASK)) {
	    uint64_t extra_bits = xtime_extra & EXT4_EPOCH_MASK;
	    ts->tv_sec += (extra_bits << 32);
	}
	ts->tv_nsec = (xtime_extra & EXT4_NSEC_MASK) >> EXT4_EPOCH_BITS;
}

static void xtime_encode(uint32_t *xtime, uint32_t *xtime_extra, struct timespec *ts)
{
	/* Extra bits: (nsec << 2 | epoch) */
	*xtime_extra = (sizeof(ts->tv_sec) > sizeof(uint32_t)) ?
			((ts->tv_sec - (int32_t)ts->tv_sec) >> 32) &
			EXT4_EPOCH_MASK : 0;
	*xtime_extra |= (ts->tv_nsec << EXT4_EPOCH_BITS);
	*xtime = ts->tv_sec;
}

static int open_extfs(struct e4b_state *st) {
	GList *lptr = st->entries;
	struct e4b_entry *first_entry = (struct e4b_entry *)lptr->data;
	struct statx *dst_info = &first_entry->dst_info;
	struct udev *udev = NULL;
	struct udev_device *dev = NULL;
	dev_t device_id = 0;
	const char* dev_name = NULL;
	io_manager io_ptr = unix_io_manager;
	int ret = 0;

	device_id = makedev(dst_info->stx_dev_major, dst_info->stx_dev_minor);

	udev = udev_new();
	if (!udev) {
		utils_err("Could not get a udev handle\n");
		return EIO;
	}

	dev = udev_device_new_from_devnum(udev, 'b', device_id);
	if (!dev) {
		utils_err("Could not find device of target fs\n");
		utils_perr("udev_device_new_from_devnum() failed");
		udev_unref(udev);
		return errno;
	}
	dev_name = udev_device_get_devnode(dev);
	udev_unref(udev);

	utils_info("Target fs device: %s\n", dev_name);

	ret = ext2fs_open(dev_name, EXT2_FLAG_RW, 0, 0, io_ptr, &st->dst_fs);
	if (ret) {
		utils_err("Could not open target filesystem for editing ctime/crtime\n");
		udev_device_unref(dev);
		return EIO;
	}
	udev_device_unref(dev);

	if (!inode_includes(EXT2_INODE_SIZE(st->dst_fs->super), i_crtime_extra)) {
		utils_wrn("Inodes on %s are not large enough to include crtime\n", dev_name);
		ext2fs_close_free(&st->dst_fs);
		return ENOTSUP;
	}
	
	return 0;
}

static void close_extfs(struct e4b_state *st)
{
	int ret = 0;
	if (st->dst_fs->flags & EXT2_FLAG_IB_DIRTY) {
		ret = ext2fs_write_inode_bitmap(st->dst_fs);
		if (ret)
			utils_err("ext2fs_write_inode_bitmap() failed\n");
	}
	/* This is probably not needed but whatever, I prefer to follow the
	 * same procedure as debugfs from ext2fstools to be on the safe
	 * side... */
	if (st->dst_fs->flags & EXT2_FLAG_BB_DIRTY) {
		ret = ext2fs_write_block_bitmap(st->dst_fs);
		if (ret)
			utils_err("ext2fs_write_block_bitmap() failed\n");
	}
	ext2fs_close_free(&st->dst_fs);
}

/* Note: I mostly wanted to preserve crtime, didn't care much about ctime, so I only check
 * for crtime support (which also means ctime_extra is also there). */
static int set_extfs_inode_times(struct e4b_entry *entry)
{
	struct e4b_state *st = entry->st;
	struct statx *src_info = &entry->src_info;
	struct statx *dst_info = &entry->dst_info;
	struct ext2_inode *inode_buf = NULL;
	struct ext2_inode_large *large_inode = NULL;
	struct timespec ts = {0};
	ext2_ino_t inode = 0;
	int ret = 0;

	utils_dbg("Updating ctime/crtime on: %s\n", entry->path);

	inode_buf = (struct ext2_inode *)malloc(EXT2_INODE_SIZE(st->dst_fs->super));
	if (!inode_buf) {
		utils_err("Could not allocate inode for editing ctime/crtime\n");
		utils_perr("malloc() failed");
		ret = errno;
		goto cleanup;
	}
  
	inode = (ext2_ino_t) dst_info->stx_ino;

	ret = ext2fs_read_inode_full(st->dst_fs, inode, inode_buf, EXT2_INODE_SIZE(st->dst_fs->super));
	if (ret) {
		utils_err("Could not read inode for editing ctime/crtime: %s\n", entry->path);
		ret = EIO;
		goto cleanup;
	}

	large_inode = (struct ext2_inode_large *)inode_buf;
	if (large_inode->i_extra_isize <
	    (offsetof(struct ext2_inode_large, i_crtime_extra) -
	     offsetof(struct ext2_inode_large, i_extra_isize) +
	     sizeof(uint32_t))) {
	     	utils_wrn("Inode not large enough to include crtime\n");
		ret = ENOTSUP;
		goto cleanup;
	}

	if (src_info->stx_mask & STATX_BTIME) {
		xtime_decode(large_inode->i_crtime, large_inode->i_crtime_extra, &ts);
		utils_dbg("current crtime: ");
		print_time(&ts, true);
		utils_dbg("\n");		

		ts.tv_sec = src_info->stx_btime.tv_sec;
		ts.tv_nsec = src_info->stx_btime.tv_nsec;
		xtime_encode(&large_inode->i_crtime, &large_inode->i_crtime_extra, &ts);

		utils_dbg("crtime set: ");
		print_time(&ts, true);
		utils_dbg("\n");
	}

	xtime_decode(large_inode->i_ctime, large_inode->i_ctime_extra, &ts);
	utils_dbg("current ctime: ");
	print_time(&ts, true);
	utils_dbg("\n");
		
	ts.tv_sec = src_info->stx_ctime.tv_sec;
	ts.tv_nsec = src_info->stx_ctime.tv_nsec;
	xtime_encode(&large_inode->i_ctime, &large_inode->i_ctime_extra, &ts);

	utils_dbg("ctime set: ");
	print_time(&ts, true);
	utils_dbg("\n");

	ret = ext2fs_write_inode_full(st->dst_fs, inode, inode_buf, EXT2_INODE_SIZE(st->dst_fs->super));
	if (ret) {
		utils_err("Could not update ctime/crtime on inode\n");
		ret = EIO;
	}

 cleanup:
 	if(inode_buf)
 		free(inode_buf);
 	return ret;
}

int update_ext4_fstimes(struct e4b_state *st)
{
	GList *lptr = NULL;
	struct e4b_entry *eptr = NULL;
	int ret = 0;

	if (!(st->opts & E4B_OPT_EXT4_FSTIMES))
		return 0;

	/* By now we should have finished with everything else so we can freeze the
	 * target fs to update inode times by hand. */
	ret = set_fs_freeze(st->dst, 1);
	if (ret) {
		utils_wrn("Could not freeze target fs, unable to preserve inode times (ctime/crtime)\n");
		return ret;
	}
		
	/* Check if target fs is ext4, note that the same magic number applies for
	 * ext2/3 so we also need to do further checks down the line. */
	if ((st->dst_fsinfo.f_type == EXT4_SUPER_MAGIC)) {
		utils_info("Opening target fs for preserving ctime/crtime\n");
		ret = open_extfs(st);
		if (ret) {
			utils_wrn("Couldn't open target fs for preserving ctime/crtime\n");
			goto cleanup;
		}
	} else
		goto cleanup;
 
	for (lptr = st->entries; lptr != NULL; lptr = lptr->next) {
		eptr = (struct e4b_entry *)lptr->data;
		/* When we re-create a hardlink on the target hierarchy we
		 * don't update dst_info so the inode number will be zero,
		 * and since we've already set ctime/crtime on the original
		 * inode there is no need to do it again. */
		if (!eptr->dst_info.stx_ino)
			continue;
		ret = set_extfs_inode_times(eptr);
		if (ret) {
			utils_dbg("set_extfs_inode_times() exited with %lu for %s\n",
				  ret, eptr->path);
			break;
		}
	}

	utils_info("Note: Updated ctime/crtime may not be visible with stat due to caching\n");
	close_extfs(st);
 cleanup:
	ret = set_fs_freeze(st->dst, 0);
	if (ret) {
		utils_wrn("Could not unfreeze target fs, run fsfreeze manualy to recover !\n");
	}
 
	return 0;
}
