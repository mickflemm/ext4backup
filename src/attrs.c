/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2022 Nick Kossifidis <mickflemm@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ext4backup.h"
#include <stddef.h>	/* For NULL */
#include <sys/stat.h>	/* For S_* macros */
#include <fcntl.h>	/* For open(), O_* flags */
#include <unistd.h>	/* For close() */
#include <sys/ioctl.h>	/* For ioctl() */
#include <linux/fs.h>	/* For  FS_IOCGET/SETFLAGS, FS_*_FL flags */

/**********************\
* ATTRS COPY/FILTERING *
\**********************/

/*
 * Preserve old-style attrs, see chattr(1):
 *
 * Those flags are set on a 32bit inode field and the full set
 * can be found in kernel's linux/fs.h included above, along with
 * a set of macros to play with. Not all FSes support them and
 * the interface for get/set is through ioctl() on the file
 * descriptor (so no O_PATH descriptors, but it's not a problem
 * since we only set those on files/directories, not symlinks).
 *
 * They are not frequently used any more, but some of them are
 * useful like the immutable attr or the flag for excluding a
 * file from backup, there are also some optimization-related
 * flags that may be useful in some cases. Note that at least
 * the immutable flag requires CAP_LINUX_IMMUTABLE to tamper
 * with, also after setting that flag we can't modify anything,
 * the inode itself is locked (so even root can't delete the
 * file, which is the primary use for that flag, to prevent
 * accidental deletion of e.g. backups). Other flags are set
 * by the OS and are not available to the user for setting/clearing
 * them, that's why we have FS_FL_USER_VISIBLE and FS_FL_USER_MODIFIABLE
 * masks seen below.
 */

void copy_attrs(struct e4b_entry *entry)
{
	struct e4b_state *st = entry->st;
	struct statx *src_info = &entry->src_info;
	int src_attr = 0;
	int dst_attr = 0;
	int ret = 0;

	if (st->opts & E4B_OPT_NO_ATTRS)
		return;

	/* Note ioctl(2) doesn't support O_PATH descriptors so if
	 * we end up here and have a descriptor for a symlink or
	 * a device this won't work. However symlinks are not
	 * supported by ioctl(2) anyway -because the only way to
	 * get a descriptor for a symlink is through O_PATH-, and
	 * devices don't usualy support FS_IOC_GETFLAGS/SETFLAGS.
	 * I've only seen lsattr working on top-level dirs under
	 * /dev (dirs that contain devices and not devices themselves)
	 * plus there is also the possibility of FS_IOC_GETFLAGS
	 * ioctl number to conflict with a device-specific ioctl
	 * so it's not safe to blindly try ioctl() on devices for
	 * retrieving file attributes.
	 * For more infos on this:
	 * https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=986332
	 */
	ret = ioctl(entry->src_fd, FS_IOC_GETFLAGS, &src_attr);
	/* Non-fatal */
	if (ret < 0) {
		utils_dbg("FS_IOC_GETFLAGS didn't work on %s\n", entry->path);
		return;
	}

	utils_dbg("attrs: 0x%X\n", src_attr);

	/* Filter out the flags we can't play with */
	src_attr &= (FS_FL_USER_VISIBLE | FS_FL_USER_MODIFIABLE);

	/* Filter out unsupported / obsolete flags */
	src_attr &= ~(FS_SECRM_FL | FS_UNRM_FL);

	/* Are we copying to an fs of the same type ? */
	if (st->dst_fsinfo.f_type != st->src_fsinfo.f_type) {
		/* Filter out some fs-specific flags */
		src_attr &= ~(FS_COMPR_FL | FS_NOCOW_FL |
			      FS_JOURNAL_DATA_FL | FS_TOPDIR_FL |
			      FS_NOTAIL_FL);
	}

	/* Ignore the immutable flag if needed */
	if (st->opts & E4B_OPT_NO_IMMUTABLES)
		src_attr &= ~FS_IMMUTABLE_FL;

	/* If we have the immutable flag set on a directory ignore
	 * it for now because we won't be able to add any more files
	 * there nor change its timestamps.  */
	if ((S_ISDIR(src_info->stx_mode)) && (src_attr & FS_IMMUTABLE_FL)) {
		utils_dbg("Immutable directory: %s\n", entry->path);
		st->immutables = g_list_prepend(st->immutables, (gpointer) entry);
		src_attr &= ~FS_IMMUTABLE_FL;
	}

	/* If we have the immutable flag set and the src inode
	 * has multiple hardlinks, ignore it for now since we
	 * won't be able to re-create hardlinks on the target fs
	 * when/if we find them while moving through the list of
	 * entries. */
	if ((src_info->stx_nlink > 1) && (src_attr & FS_IMMUTABLE_FL)) {
		utils_dbg("Immutable file with multiple hardlinks: %s\n", entry->path);
		st->immutables = g_list_prepend(st->immutables, (gpointer) entry);
		src_attr &= ~FS_IMMUTABLE_FL;
	}

	utils_dbg("attrs (sanitized): 0x%X\n", src_attr);

	if (!src_attr)
		return;

	/* We could try and set one flag at a time for improved
	 * debug output but it's not worth the complexity and
	 * performance penalty of multiple syscalls, we 'd also
	 * need to handle the immutable flag differently etc,
	 * I don't think it's worth it, so just try and set them
	 * all together and if it fails print a warning message
	 * so that the user can handle this later on by hand. */

	/* Note: we can't just use flags on src_attr, we need to OR them
	 * to the attrs of the target that may include flags that are
	 * not user visible or modifiable, or else we'll get an error. */
	ret = ioctl(entry->dst_fd, FS_IOC_GETFLAGS, &dst_attr);
	if (ret < 0) {
		utils_wrn("Could not get target attrs for editing: %s\n", entry->path);
		utils_wrn("ioctl() failed: %s\n", strerror(errno));
		return;
	}

	dst_attr |= src_attr;

	ret = ioctl(entry->dst_fd, FS_IOC_SETFLAGS, &dst_attr);
	/* Non-fatal */
	if (ret < 0) {
		utils_wrn("Could not set attrs (0x%X): %s\n", src_attr, entry->path);
		utils_wrn("ioctl() failed: %s\n", strerror(errno));
	}

	return;
}

static int set_immutable(struct e4b_entry *entry, struct e4b_state *st)
{
	struct statx *src_info = &entry->src_info;
	int open_flags = O_RDWR | O_NOFOLLOW | O_NOATIME;
	int dst_fd = 0;
	int dst_attr = 0;
	int ret = 0;

	if (!S_ISDIR(src_info->stx_mode) && !S_ISREG(src_info->stx_mode)) {
		utils_err("Error invalid entry in immutables list !\n");
		return EINVAL;
	}

	utils_dbg("Restoring immutable flag on target: %s\n", entry->path);

	if (S_ISDIR(src_info->stx_mode))
		open_flags |= O_DIRECTORY;

	dst_fd = TEMP_FAILURE_RETRY(openat(st->dst_dirfd, entry->path, open_flags, 0));
	if (dst_fd < 0) {
		utils_wrn("Could not open target for attr editing: %s\n", entry->path);
		utils_wrn("openat() failed: %s\n", strerror(errno));
		goto cleanup;
	}

	ret = ioctl(dst_fd, FS_IOC_GETFLAGS, &dst_attr);
	if (ret < 0) {
		utils_wrn("Could not get target attrs for editing: %s\n", entry->path);
		utils_wrn("ioctl() failed: %s\n", strerror(errno));
		goto cleanup;
	}

	dst_attr |= FS_IMMUTABLE_FL;

	ret = ioctl(dst_fd, FS_IOC_SETFLAGS, &dst_attr);
	if (ret < 0) {
		utils_wrn("Could not set immutable flag: %s\n", entry->path);
		utils_wrn("ioctl() failed: %s\n", strerror(errno));
	}

 cleanup:
 	if (dst_fd > 0)
		close(dst_fd);
	return 0;
}

int update_immutables(struct e4b_state *st)
{
	GList *lptr = NULL;
	struct e4b_entry *eptr = NULL;
	int ret = 0;

	if ((st->opts & E4B_OPT_NO_ATTRS) || (st->opts & E4B_OPT_NO_IMMUTABLES))
		return 0;

	for (lptr = st->immutables; lptr != NULL; lptr = lptr->next) {
		eptr = (struct e4b_entry *)lptr->data;
		ret = set_immutable(eptr, st);
		if (ret) {
			utils_dbg("set_immutable() exited with %lu for %s\n",
				  ret, eptr->path);
			return ret;
		}
	}

	return 0;
}
