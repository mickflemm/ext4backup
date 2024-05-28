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
#include <fts.h>	/* For fts() */

/*********\
* HELPERS *
\*********/

struct e4b_entry* alloc_src_entry(int trimed_pathlen)
{
	int entry_len = sizeof(struct e4b_entry) + trimed_pathlen + 1;
	struct e4b_entry *e = NULL;
	char *path = NULL;

	e = malloc(sizeof(struct e4b_entry));
	if (!e) {
		errno = ENOMEM;
		return NULL;
	}
	memset(e, 0, sizeof(struct e4b_entry));

	path = malloc(trimed_pathlen + 1);
	if (!path) {
		free(e);
		errno = ENOMEM;
		return NULL;
	}
	memset(path, 0, trimed_pathlen + 1);

	e->path = path;
	return e;
}

void free_src_entry(void* in)
{
	struct e4b_entry *e = (struct e4b_entry *) in;
	if (e->path)
		free(e->path);
	free(e);
}

/*****************\
* STATE INIT/FREE *
\*****************/

static int traverse_file_hierarchy(struct e4b_state *st, const char* rootpath, bool source)
{
	FTS *fs_stream = NULL;
	FTSENT *fs_stream_entry = NULL;
	struct statx stx_tmp = {0};
	char* paths[2] = { (char*) rootpath, NULL };
	int fts_opts = FTS_PHYSICAL | FTS_NOCHDIR | FTS_NOSTAT | (source ? FTS_XDEV : 0);
	const char *trimed = NULL;
	int trimed_pathlen = 0;
	int ret = 0;

	fs_stream = fts_open(paths, fts_opts, NULL);
	if (!fs_stream) {
		utils_err("fts_open() failed on %s hierarchy: %s\n",
				  (source ? "source" : "target"), strerror(errno));
		return errno;
	}

	/* Walk the tree and add entries to the source/destination list
	 * depending on the source switch */
	while ((fs_stream_entry = fts_read(fs_stream)) && (fs_stream_entry != NULL))
	{
		switch (fs_stream_entry->fts_info) {
		case FTS_D:
			/* Ignore the root directory, we only care about its contents */
			if (!fs_stream_entry->fts_level)
				continue;
			/* If a non-recursive walk was requested skip any subdirs */
			if (fs_stream_entry->fts_level > 0 && (st->opts & E4B_OPT_NONRECURSIVE)) {
				utils_dbg("Ignoring subdir: %s\n", fs_stream_entry->fts_path);
				ret = fts_set(fs_stream, fs_stream_entry, FTS_SKIP);
				if (ret == -1) {
					utils_perr("fts_set() failed");
					fts_close(fs_stream);
					return errno;
				}
				continue;
			}
			/* The following checks only apply to source, we ignore them on target */
			if (!source)
				continue;
			/* We need to do a statx now to check the directory's attributes */
			ret = get_path_info(fs_stream_entry->fts_path, 0, &stx_tmp, 0);
			if (ret) {
				fts_close(fs_stream);
				return ret;
			}
			/* If the directory is marked with NODUMP and we obey NODUMP, skip it */
			if ((stx_tmp.stx_attributes & STATX_ATTR_NODUMP) &&
				!(st->opts & E4B_OPT_IGNORE_NODUMP)) {
					utils_dbg("Ignoring subdir marked with nodump: %s\n",
							  fs_stream_entry->fts_path);
					ret = fts_set(fs_stream, fs_stream_entry, FTS_SKIP);
					if (ret == -1) {
						utils_perr("fts_set() failed");
						fts_close(fs_stream);
						return errno;
					}
			}
			/* Skip encrypted dirs that we can't process */
			/* Note: There are some limitations in the current user API,
			 * for regular files we can try and open them and fail with ENOKEY,
			 * for directories we can open them and use ioctls to see if the key
			 * used for their encryption is present, but for symlinks we can do
			 * nothing (ioctl doesn't accept O_PATH descriptors). Another issue
			 * (which is also a security threat) is that in order to backup the
			 * encrypted files, they should get unlocked beforehand, opening a
			 * window of opportunity to an attacker. According to the docs there
			 * will be an API for backing up encrypted files but it's not there yet.
			 * Since the idea is that fscrypt handles directories and not individual
			 * files, we can assume that checking if the encryption key for this
			 * directory is present, we are good to go, otherwise warn the user
			 * and skip this directory because we won't be able to read it. */
			if (stx_tmp.stx_attributes & STATX_ATTR_ENCRYPTED) {
				if (st->opts & E4B_OPT_COPY_ENCRYPTED) {
					ret = is_key_available(fs_stream_entry->fts_path);
					if (ret == 0 || ret < 0) {
						if (ret == 0)
							utils_err("Key not present for: %s\n",
								  fs_stream_entry->fts_path);
						else
							utils_err("Could not determine key status for: %s\n",
								  fs_stream_entry->fts_path);
						ret = fts_set(fs_stream, fs_stream_entry, FTS_SKIP);
						if (ret == -1) {
							utils_perr("fts_set() failed");
							fts_close(fs_stream);
							return errno;
						}
					}
				} else {
					utils_dbg("Ignoring encrypted subdir: %s\n",
							  fs_stream_entry->fts_path);
					ret = fts_set(fs_stream, fs_stream_entry, FTS_SKIP);
					if (ret == -1) {
						utils_perr("fts_set() failed");
						fts_close(fs_stream);
						return errno;
					}
				}
			}
			/* We don't care for ordering in case of the target hierarchy, since
			 * we'll use a hashtable, but for the source hierarchy in the end we
			 * want to be sure that we'll see directories before their contents,
			 * so that we can re-create them in the target. However to avoid
			 * appending the entries to glist (see below), and walking the whole
			 * list every time, it makes more sense to prepend them, and to avoid
			 * reversing the list afterwards we add the directories after their
			 * contents here, so continue for FTS_D and break for FTS_DP. */
			continue;
		case FTS_DP:
			if (!fs_stream_entry->fts_level)
				continue;
			else
				break;
		case FTS_DEFAULT:
			/* This is not a regular file/directory/symlink, if user doesn't care
			 * about special files, ignore it. */
			if (st->opts & E4B_OPT_NO_SPECIAL)
				continue;
		case FTS_DNR:
		case FTS_ERR:
			utils_err("Error when visiting: %s\n\t%s\n", fs_stream_entry->fts_path,
					  strerror(fs_stream_entry->fts_errno));
			if (st->opts & E4B_OPT_KEEP_GOING)
				continue;
			else {
				fts_close(fs_stream);
				return fs_stream_entry->fts_errno;
			}
		default:
			break;
		}

		/* Note: https://bugzilla.kernel.org/show_bug.cgi?id=216275 */
		trimed = fs_stream_entry->fts_path + (source ? st->src_len : st->dst_len) + 1;
		trimed_pathlen = strnlen(trimed, PATH_MAX);
		utils_dbg("Got file on %s: %s\n", (source ? "source" : "target"), trimed);

		/* For the source hierarchy create the e4b_entry objects we'll use for copying,
		 * for the target hierarchy we only need a copy of the path and a struct statx. */
		if (source) {
			struct e4b_entry *entry = NULL;
			struct statx *src_info = NULL;

			entry = alloc_src_entry(trimed_pathlen);
			if (!entry) {
				utils_perr("Could not allocate entry");
				fts_close(fs_stream);
				return ENOMEM;
			}

			entry->st = st;
			entry->depth = fs_stream_entry->fts_level;
			entry->base = trimed_pathlen - fs_stream_entry->fts_namelen;

			src_info = &entry->src_info;
			strncpy(entry->path, trimed, trimed_pathlen + 1);
			ret = get_path_info(fs_stream_entry->fts_path, 0, src_info, 0);
			if (ret) {
				free(entry);
				fts_close(fs_stream);
				return ret;
			}

			st->entries = g_list_prepend(st->entries, (gpointer) entry);
			st->num_entries++;
			st->data_len += src_info->stx_size;
		} else {
			char* dst_path = NULL;
			struct statx *dst_info = NULL;
			dst_path = malloc(trimed_pathlen + 1);
			if (!dst_path) {
				utils_perr("Could not allocate dst_path");
				fts_close(fs_stream);
				return ENOMEM;
			}
			dst_info = malloc(sizeof(struct statx));
			if (!dst_info) {
				utils_perr("Could not allocate stx_copy");
				free(dst_path);
				fts_close(fs_stream);
				return ENOMEM;
			}
			strncpy(dst_path, trimed, trimed_pathlen + 1);
			ret = get_path_info(fs_stream_entry->fts_path, 0, dst_info, 0);
			if (ret) {
				free(dst_path);
				free(dst_info);
				fts_close(fs_stream);
				return ret;
			}
			g_hash_table_insert(st->existing, (void*) dst_path, dst_info);
		}
	}

	fts_close(fs_stream);
	return 0;
}

static void prepare_entry(gpointer data, gpointer user_data)
{
	struct e4b_entry *entry = (struct e4b_entry *) data;
	struct e4b_state *st = (struct e4b_state *) user_data;
	struct statx *dst_info = NULL;

	utils_dbg("Filename: %s, base: %i, depth: %i\n", entry->path, entry->base, entry->depth);

	/* Check if the same file exists on target and grab dst_info */
	dst_info = g_hash_table_lookup(st->existing, entry->path);
	if (!dst_info)
		return;

	utils_dbg("File %s exists on target\n", entry->path);

	/* If we don't do updates clear the path of this entry so that
	 * we skip it during processing */
	if (st->opts & E4B_OPT_NO_UPDATE) {
		free(entry->path);
		entry->path = NULL;
		return;
	}

	memcpy(&entry->dst_info, dst_info, sizeof(struct statx));

	st->existing_data_len += dst_info->stx_size;

	/* If purge was requested remove any files from st->existing
	 * that also exist on source, so that st->existing only contains
	 * excess files after we are done. */
	if (st->opts & E4B_OPT_PURGE_EXCESS)
		g_hash_table_remove(st->existing, entry->path);
}

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
	if (st->existing)
		g_hash_table_destroy(st->existing);
	if (st->hardlinks)
		g_hash_table_destroy(st->hardlinks);
	if (st->unsupported_xattrs)
		g_hash_table_destroy(st->unsupported_xattrs);
	if (st->entries)
		g_list_free_full(st->entries, free_src_entry);
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
	struct e4b_state *e4bst = NULL;
	struct statx src_info = { 0 };
	struct statx dst_info = { 0 };
	char* src = NULL;
	char* dst = NULL;
	int max_fds = sysconf(_SC_OPEN_MAX) - 3;
	ssize_t xattr_test = 0;
	off_t data_len_check = 0;
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

	if (!(opts & E4B_OPT_IGNORE_TARGET)) {
		e4bst->dst_len = strnlen(dst, PATH_MAX);
		/* Initialize the hashtable for tracking existing files/directories on target, and
		 * populate it. */
		e4bst->existing = g_hash_table_new_full(g_str_hash, g_str_equal, free, free);
		ret = traverse_file_hierarchy(e4bst, dst, 0);
		if (ret) {
			utils_err("Could not traverse target hierarchy\n");
			if  (e4bst->opts & E4B_OPT_PURGE_EXCESS) {
				e4bst->opts &= ~E4B_OPT_PURGE_EXCESS;
				utils_wrn("Will not purge excess files/directories from target hierarchy\n");
			}
		}
	} else {
		e4bst->opts &= ~E4B_OPT_PURGE_EXCESS;
		e4bst->existing = NULL;
		e4bst->existing_data_len = 0;
	}

	ret = traverse_file_hierarchy(e4bst, src, 1);
	if (ret) {
		utils_err("Could not traverse source hierarchy\n");
		ret = errno;
		goto cleanup;
	}

	g_list_foreach(e4bst->entries, prepare_entry, e4bst);

	if (!(e4bst->opts & E4B_OPT_PURGE_EXCESS)) {
		/* No need to keep the hashtable around, clean it up. */
		g_hash_table_destroy(e4bst->existing);
		e4bst->existing = NULL;
	}

	/* Make sure there is enough space on dst */
	utils_info("Data length: %s\n", print_size(e4bst->data_len));
	data_len_check = e4bst->data_len;
	if (e4bst->existing_data_len) {
			utils_info("Data length of existing files/dirs on target: %s\n",
					   print_size(e4bst->existing_data_len));
			data_len_check -= e4bst->existing_data_len;
	}
	if (((e4bst->dst_fsinfo.f_bavail * e4bst->dst_fsinfo.f_frsize) < data_len_check) &&
	   !(opts & (E4B_OPT_NO_DATA | E4B_OPT_NO_SPACE_CHECK))) {
		utils_err("Not enough space on destination filesystem\n");
		utils_err("Required: %s\n", print_size(data_len_check));
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
