/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2022 Nick Kossifidis <mickflemm@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ext4backup.h"
#include <stddef.h>	/* For NULL */
#include <stdio.h>	/* For snprintf() */
#include <fcntl.h>	/* For AT_* flags */
#include <unistd.h>	/* For fchownat(), close() */
#include <sys/stat.h>	/* For S_* flags */

/*******************\
* METADATA TRANSFER *
\*******************/

int copy_metadata(struct e4b_entry *entry)
{
	struct e4b_state *st = entry->st;
	struct statx *src_info = &entry->src_info;
	struct statx *dst_info = &entry->dst_info;
	char src_fdpath[20] = {0};	/* "/proc/self/fd/XXXX" */
	char dst_fdpath[20] = {0};	/* 19 +1 for alignment */
	struct timespec times[2] = {0};
	int ret = 0;

	if (st->opts & E4B_OPT_NO_METADATA)
		goto cleanup;

	/* Update dst info, by now it should exist no matter what. */
	ret = get_path_info(NULL, entry->dst_fd, dst_info, false);
	if (ret)
		goto cleanup;

	/* Unfortunately there is no support of O_PATH descriptors and
	 * the AT_EMPTY_PATH flag for some of the syscalls we want
	 * (xattrs stuff, fchmodat etc), so we do this little trick to
	 * use paths instead. Note that in case of symlinks those will
	 * resolve to the symlink itself which is what we want. */
	snprintf(src_fdpath, 19, "/proc/self/fd/%i", entry->src_fd);
	snprintf(dst_fdpath, 19, "/proc/self/fd/%i", entry->dst_fd);

	/* Preserve/update ownership if needed */
	if ((src_info->stx_uid == dst_info->stx_uid) &&
	    (src_info->stx_gid == dst_info->stx_gid))
		goto preserve_utimes;

	ret = fchownat(entry->dst_fd, "", src_info->stx_uid, src_info->stx_gid,
		       AT_EMPTY_PATH);
	if (ret < 0) {
		utils_err("Error while setting ownership on:\n\t%s\n",
			  entry->path);
		utils_perr("fchownat() failed");
		ret = errno;
		goto cleanup;
	}

 preserve_utimes:

	/* Don't bother updating timestamps on dirs for now,
	 * will update them after copying files. */
	if (S_ISDIR(src_info->stx_mode))
		goto preserve_xattrs;

	times[0].tv_sec = src_info->stx_atime.tv_sec;
	times[0].tv_nsec = src_info->stx_atime.tv_nsec;

	times[1].tv_sec = src_info->stx_mtime.tv_sec;
	times[1].tv_nsec = src_info->stx_mtime.tv_nsec;

	ret = utimensat(entry->dst_fd, "", times, AT_EMPTY_PATH);
	if (ret < 0) {
		utils_err("Error while setting atime/mtime on:\n\t%s\n",
			  entry->path);
		utils_perr("utimensat() failed");
		ret = errno;
		goto cleanup;
	}

 preserve_xattrs:

	ret = copy_xattrs(src_fdpath, dst_fdpath, entry);
	if (ret)
		goto cleanup;

	/* Bellow don't apply to symlinks */
	if (S_ISLNK(src_info->stx_mode))
		goto cleanup;

	/* Preserve permissions */
#define PERMS_MASK (S_IRWXU | S_IRWXG | S_IRWXO | S_ISUID | S_ISGID | S_ISVTX)
	if ((src_info->stx_mode & PERMS_MASK) == (dst_info->stx_mode & PERMS_MASK))
		goto preserve_attrs;
#undef PERMS_MASK

	ret = chmod(dst_fdpath, src_info->stx_mode);
	if (ret < 0) {
		utils_err("Error while setting permissions on:\n\t%s\n",
			  entry->path);
		utils_perr("chmod() failed");
		goto cleanup;
	}

	ret = 0;

 preserve_attrs:

 	/* We leave this for last since it may set the immutable flag
 	 * in which case we won't be able to do anything else with the
 	 * file/inode afterwards. We only do this for regular files and
 	 * dirs, read the comments in copy_attrs() for more infos. */
 	if (S_ISDIR(src_info->stx_mode) || S_ISREG(src_info->stx_mode))
		copy_attrs(entry);

 cleanup:
	close(entry->src_fd);
	close(entry->dst_fd);
	return ret;
}

static int update_subdir_times(struct e4b_entry *entry, struct e4b_state *st)
{
	struct statx *src_info = &entry->src_info;
	struct timespec times[2] = {0};
	int ret = 0;

	if (!S_ISDIR(src_info->stx_mode)) {
		utils_err("Error invalid entry in subdirs list !\n");
		return EINVAL;
	}

	times[0].tv_sec = src_info->stx_atime.tv_sec;
	times[0].tv_nsec = src_info->stx_atime.tv_nsec;

	times[1].tv_sec = src_info->stx_mtime.tv_sec;
	times[1].tv_nsec = src_info->stx_mtime.tv_nsec;

	utils_dbg("Updating utimes for: %s\n", entry->path);
	ret = utimensat(st->dst_dirfd, entry->path, times, AT_SYMLINK_NOFOLLOW);
	if (ret < 0) {
		utils_err("Error while updating atime/mtime on dir:\n\t%s\n",
			  entry->path);
		utils_perr("utimensat() failed");
		return errno;
	}

	return 0;
}

int update_subdirs(struct e4b_state *st)
{
	GList *lptr = NULL;
	struct e4b_entry *eptr = NULL;
	int ret = 0;

	for (lptr = st->subdirs; lptr != NULL; lptr = lptr->next) {
		eptr = (struct e4b_entry *)lptr->data;
		ret = update_subdir_times(eptr, st);
		if (ret) {
			utils_dbg("update_subdir_times() exited with %lu for %s\n",
				  ret, eptr->path);
			return ret;
		}
	}

	return 0;
}
