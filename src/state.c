/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2022 Nick Kossifidis <mickflemm@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ext4backup.h"
#include <stddef.h>	/* For NULL */
#include <limits.h>	/* For realpath() */
#include <stdlib.h>	/* For malloc(), free(), memcpy(), realpath() */
#include <unistd.h>	/* For sysconf() */
#include <fcntl.h>	/* For open() */
#include <sys/vfs.h>	/* For statfs() */
#include <sys/xattr.h>	/* For listxattr() */
#include <ftw.h>	/* For nftw() */
#include <glib.h>	/* For GList/GHashtable */
#include <errno.h>	/* For error codes */
#include <string.h>	/* For strnlen(), memset(), strncpy() */

/*****************\
* STATE INIT/FREE *
\*****************/

/* We use this since we can't pass a user argument to nftw */
static struct e4b_state *e4bst = NULL;

static int init_entry(const char *filepath, const struct stat *info,
		      const int typeflag, struct FTW *pathinfo)
{
	struct statx src_info = {0};
	struct e4b_entry *entry = NULL;
	const char *trimed = NULL;
	int entry_pathlen = 0;
	int entry_len = 0;
	int ret = FTW_CONTINUE;

	if (!filepath || !info || !pathinfo) {
		utils_err("Missing arguments to fill_dir_entries()\n");
		errno = EINVAL;
		return FTW_STOP;
	}

	/* Don't add the source directory itself to the list */
	if (!pathinfo->level && !entry_pathlen)
		return FTW_CONTINUE;

	/* If NONRECURSIVE was requested skip any subdirectories */
	if ((typeflag == FTW_D) && (pathinfo->level > 0)
	    && (e4bst->opts & E4B_OPT_NONRECURSIVE))
		ret = FTW_SKIP_SUBTREE;

	/* Get more infos about the file using statx */
	ret = get_path_info(filepath, 0, &src_info, 0);
	if (ret) {
		errno = ret;
		return FTW_STOP;
	}

	/* Handle files/directories marked with NODUMP */
	if ((src_info.stx_attributes & STATX_ATTR_NODUMP) &&
	    !(e4bst->opts & E4B_OPT_IGNORE_NODUMP)) {
	    	utils_wrn("Skipping path marked with NODUMP: %s\n", filepath);
		if (typeflag == FTW_D)
			ret = FTW_SKIP_SUBTREE;
		else
			return FTW_CONTINUE;
	}

	/* Skip encrypted files that we can't process */
	/* Note: We can't handle encrypted files with the current user API,
	 * for regular files we can try and open them and fail with ENOKEY,
	 * for directories we can open them and use ioctls to see if the key
	 * used for their encryption is present, but for symlinks we can do
	 * nothing (ioctl doesn't accept O_PATH descriptors). According to
	 * the docs there will be an API for backing up encrypted files
	 * but it's not there yet. So for now warn the user and let the
	 * user copy the encrypted files manualy after adding the key to
	 * the keyring/unlocking them. As an alternative, check for the
	 * E4B_OPT_COPY_ENCRYPTED option and assume the user has already
	 * provided the encryption keys needed. */
	if (src_info.stx_attributes & STATX_ATTR_ENCRYPTED &&
	    !(e4bst->opts & E4B_OPT_COPY_ENCRYPTED)) {
		utils_wrn("Skipping encrypted file: %s\n", filepath);
		return FTW_CONTINUE;
	}

	trimed = filepath + e4bst->src_len + 1;
	entry_pathlen = strnlen(trimed, PATH_MAX);
	entry_len = sizeof(struct e4b_entry) + entry_pathlen + 1;

	entry = malloc(entry_len);
	if (!entry) {
		utils_perr("Could not allocate entry");
		errno = ENOMEM;
		return FTW_STOP;
	}
	memset(entry, 0, entry_len);
	entry->st = e4bst;
	strncpy(entry->path, trimed, entry_pathlen + 1);
	memcpy(&entry->src_info, &src_info, sizeof(struct statx));
	entry->depth = pathinfo->level;

	/* pathinfo->base is the offset of the basename component on
	 * filepath, since we strip the source directory part from filepath
	 * on entry->path, we do the same for entry->base. */
	entry->base = pathinfo->base - (e4bst->src_len + 1);

	/* Note: prepend instead of append, to avoid the need to
	 * traverse the list on every addition, we'll reverse the
	 * list afterwards. */
	e4bst->entries = g_list_prepend(e4bst->entries, (gpointer) entry);
	e4bst->num_entries++;
	e4bst->data_len += info->st_size;
	
	return FTW_CONTINUE;
}

#ifdef DEBUG
static void print_entry(gpointer data, gpointer user_data)
{
	struct e4b_entry *entry = (struct e4b_entry *)data;
	utils_info("Filename: %s\n", entry->path);
}
#endif

static void clear_state(struct e4b_state *st)
{
	int ret = 0;
 	if (st->src_frozen) {
		ret = set_fs_freeze(st->src, 0);
		if (ret) {
			utils_err("Could not unfreeze source fs, run fsfreeze manualy to recover !\n");
		}
	}
	if (st->src)
		free(st->src);
	if (st->dst)
		free(st->dst);
	if (st->hardlinks)
		g_hash_table_destroy(st->hardlinks);
	if (st->unsupported_xattrs)
		g_hash_table_destroy(st->unsupported_xattrs);
	if (st->entries)
		g_list_free_full(st->entries, free);
	/* Note: entries are re-used on subdirs and immutables */
	if (st->subdirs)
		g_list_free(st->subdirs);
	if (st->immutables)
		g_list_free(st->immutables);
	if (st->skip_xattr_patterns)
		g_list_free_full(st->skip_xattr_patterns, free);
}

int init_state(const char* src_in, const char* dst_in, int opts, struct e4b_state **st)
{
	struct statx src_info = { 0 };
	struct statx dst_info = { 0 };
	char* src = NULL;
	char* dst = NULL;
	int max_fds = sysconf(_SC_OPEN_MAX) - 3;
	ssize_t xattr_test = 0;
	int ret = 0;

	e4bst = malloc(sizeof(struct e4b_state));
	if (!e4bst) {
		utils_err("Could not allocate new state\n");
		return ENOMEM;
	}
	memset(e4bst, 0, sizeof(struct e4b_state));

	e4bst->opts = opts;

	/* Get information about the source dir/fs */
	src = realpath(src_in, NULL);
	if (!src) {
		utils_perr("realpath() failed for source dir");
		ret = errno;
		goto cleanup;
	}

	ret = get_path_info(src, 0, &src_info, false);
	if (ret)
		goto cleanup;
		
	ret = TEMP_FAILURE_RETRY(statfs(src, &e4bst->src_fsinfo));
	if (ret) {
		utils_perr("statfs() failed for source dir");
		ret = errno;
		goto cleanup;
	}

	/* Check if the source fs supports xattrs */
	xattr_test = listxattr(src, NULL, 0);
	if (xattr_test < 0) {
		if (errno == ENOTSUP || errno == ENOSYS)
			e4bst->src_xattrs_disabled = true;
		else {
			utils_perr("listxattr() failed for source dir");
			ret = errno;
			goto cleanup;
		}
	}

	/* Initialize src_dirfd so that we use *at syscalls and relative paths when
	 * processing entries (otherwise we 'd need to re-create the full source and
	 * destination path for each entry). */
	e4bst->src_dirfd = TEMP_FAILURE_RETRY(open(src, O_DIRECTORY | O_NOFOLLOW | O_RDONLY, 0));
	if (e4bst->src_dirfd < 0) {
		utils_err("Error while opening source:\n\t%s\n", src);
		utils_perr("open() failed");
		ret = errno;
		goto cleanup;
	}

	
	/* Same for target directory/fs */
	dst = realpath(dst_in, NULL);
	if (!dst) {
		utils_perr("realpath() failed for destination dir");
		ret = errno;
		goto cleanup;
	}

	ret = get_path_info(dst, 0, &dst_info, false);
	if (ret)
		goto cleanup;

	/* Sanity check: Make sure src and dst are directories */
	if (((src_info.stx_mode & S_IFMT) != S_IFDIR) ||
	    ((dst_info.stx_mode & S_IFMT) != S_IFDIR)) {
		utils_err("Invalid arguments, make sure both source and destination are directories\n");
		ret = EINVAL;
		goto cleanup;
	}

	/* Sanity check: Make sure source and destination are not the same dir */
	if (src_info.stx_ino == dst_info.stx_ino &&
	    src_info.stx_dev_major == dst_info.stx_dev_major &&
	    src_info.stx_dev_minor == dst_info.stx_dev_minor) {
		utils_err("Source and destination are the same dir\n");
		ret = EINVAL;
		goto cleanup;    
	}
	
	ret = TEMP_FAILURE_RETRY(statfs(dst, &e4bst->dst_fsinfo));
	if (ret) {
		utils_perr("statfs() failed for destination dir");
		ret = errno;
		goto cleanup;
	}

	xattr_test = listxattr(dst, NULL, 0);
	if (xattr_test < 0) {
		if (errno == ENOTSUP || errno == ENOSYS)
			e4bst->dst_xattrs_disabled = true;
		else {
			utils_perr("listxattr() failed for target dir");
			ret = errno;
			goto cleanup;
		}
	}

	e4bst->dst_dirfd = TEMP_FAILURE_RETRY(open(dst, O_DIRECTORY | O_NOFOLLOW | O_RDONLY, 0));
	if (e4bst->dst_dirfd < 0) {
		utils_err("Error while opening target:\n\t%s\n", dst);
		utils_perr("open() failed");
		ret = errno;
		goto cleanup;
	}

	/* Sanity check: Make sure dst filesystem is mounted rw */
	if (e4bst->dst_fsinfo.f_flags & ST_RDONLY) {
		utils_err("Destination filesystem is mounted as readonly\n");
		ret = EROFS;
		goto cleanup;
	}

	/* (just to be on the safe side) make sure dst filesystem
	 * has a large enough namelen */
	if (e4bst->dst_fsinfo.f_namelen < e4bst->src_fsinfo.f_namelen) {
		utils_err("Destination filesystem can't hold as large namelen as the source\n");
		ret = ENAMETOOLONG;
		goto cleanup;
	}

	/* Attempt to freeze source fs so that we get a consistent backup and not have any
	 * modifications while we copy. */

	/* But first make sure source and destination are on different fs or else we won't be
	 * able to copy anything. */
	if (src_info.stx_dev_major == dst_info.stx_dev_major &&
	    src_info.stx_dev_minor == dst_info.stx_dev_minor) {
		utils_wrn("Source and destination are on the same device, we can't freeze the source fs\n");
		utils_wrn("Backup may be inconsistent\n");
	} else {
		if (!(opts & E4B_OPT_NO_FSFREEZE)) {
			ret = set_fs_freeze(src, 1);
			if (ret) {
				utils_wrn("Could not freeze source fs, backup may be inconsistent\n");
			} else
				e4bst->src_frozen = true;
		} else {
			utils_wrn("FSFreeze disabled, backup may be inconsistent\n");
		}
	}

	/* Let's find out what we are dealing with, gather the list of stuff we need to copy */
	e4bst->src = src;
	e4bst->src_len = strnlen(src, PATH_MAX);
	e4bst->dst = dst;
	utils_info("Source: %s\n", e4bst->src);
	utils_info("Destination: %s\n", e4bst->dst);

	ret = nftw(e4bst->src, init_entry, max_fds, FTW_PHYS | FTW_MOUNT | FTW_ACTIONRETVAL);
	if (ret < 0) {
		utils_perr("Could not traverse source hierarchy, nftw() failed");
		ret = errno;
		goto cleanup;
	} else if (ret > 0) {
		utils_err("Could not traverse source hierarchy\n");
		ret = errno;
		goto cleanup;
	}

	/* On init_entry() we prepend entries to the list so that we don't have
	 * to walk it each time, time to reverse it to get the entries in order. */
	e4bst->entries = g_list_reverse(e4bst->entries);

	/* Make sure there is enough space on dst */
	utils_info("Data length: %s\n", print_size(e4bst->data_len));
	if ((e4bst->dst_fsinfo.f_bavail * e4bst->dst_fsinfo.f_frsize) < e4bst->data_len) {
		utils_err("Not enough space on destination filesystem\n");
		utils_err("Required: %s\n", print_size(e4bst->data_len));
		utils_err("Available: %s\n", print_size(e4bst->dst_fsinfo.f_bavail *
							e4bst->dst_fsinfo.f_frsize));
		ret = ENOSPC;
		goto cleanup;
	}

	/* Initialize the hashtable for tracking hardlinks. */
	e4bst->hardlinks = g_hash_table_new(g_int64_hash, g_int64_equal);

	/* Initialize the hashtable for tracking unsupported xattrs. */
	e4bst->unsupported_xattrs = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);

	/* Initialize list of xattr patterns to ignore, from /etc/xattr.conf */
	ret = fill_skip_xattr_patterns(e4bst);

#ifdef DEBUG
	g_list_foreach(e4bst->entries, print_entry, NULL);
#endif

	ret = 0;

 cleanup:
 	if (ret) {
 		clear_state(e4bst);
 		*st = NULL;
 		return ret;
 	}

	*st = e4bst;
	e4bst = NULL;
	return 0;
}

void free_state(struct e4b_state *st) {
	clear_state(st);
	free(st);
}
