/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2022 Nick Kossifidis <mickflemm@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ext4backup.h"
#include <stddef.h>	/* For NULL */
#include <stdlib.h>	/* For free() */
#include <fcntl.h>	/* For openat(), O_* flags, AT_* flags */
#include <unistd.h>	/* For linkat(), unlinkat(), symlinkat(), close() */
#include <sys/stat.h>	/* For S_* flags, mknodat() */
#include <sys/sysmacros.h> /* For makedev() */
#include <glib.h>	/* For GList/GHashtable */
#include <errno.h>	/* For error codes */
#include <string.h>	/* For strerror() */

/*********\
* HELPERS *
\*********/

static inline bool timestamp_lt(struct statx_timestamp *a, struct statx_timestamp *b)
{
	return (((a)->tv_sec == (b)->tv_sec) ?
		((a)->tv_nsec < (b)->tv_nsec) : ((a)->tv_sec < (b)->tv_sec));
}

static inline bool timestamp_eq(struct statx_timestamp *a, struct statx_timestamp *b)
{
	return (((a)->tv_sec == (b)->tv_sec) && ((a)->tv_nsec == (b)->tv_nsec));
}


/*****************************\
* MAIN PROCESSING ENTRY POINT *
\*****************************/

static int process_entry(struct e4b_entry *entry)
{
	struct e4b_state *st = entry->st;
	struct statx *src_info = &entry->src_info;
	struct statx *dst_info = &entry->dst_info;
	char *lnk_path = NULL;
	bool dst_exists = false;
	int skip_copy = (st->opts & E4B_OPT_NO_DATA);
	const char *node_type = "(block / char device)";
	dev_t device_id = {0};
	int src_open_flags = 0;
	int dst_open_flags = 0;
	int ret = 0;

	utils_dbg("\nCopying from: \n\t%s/%s\nto:\n\t%s/%s\n",
		  st->src, entry->path, st->dst, entry->path);

	/* In case we couldn't freeze the source fs, update src_info as
	 * a best effort to handle files that got modified since
	 * fill_dir_entries() */
	if (!st->src_frozen) {
		ret = get_path_info(entry->path, st->src_dirfd, src_info, false);
		if (ret)
			return ret;
	}

	/* Check if the destination exists and if it needs updating */
	ret = get_path_info(entry->path, st->dst_dirfd, dst_info, true);
	if (ret != 0) {
		if (ret != ENOENT)
			return ret;
	} else {
		dst_exists = true;

		/* Sanity check: Is source and destination the same file ? */
		if (src_info->stx_ino == dst_info->stx_ino &&
		    src_info->stx_dev_major == dst_info->stx_dev_major &&
		    src_info->stx_dev_minor == dst_info->stx_dev_minor) {
			utils_wrn("Source and destination are the same file:\n\t%s\n",
				  entry->path);
			return 0;
		}

		/* Sanity check: Are both source and destination of the same type ? */
		if ((src_info->stx_mode & S_IFMT) != (dst_info->stx_mode & S_IFMT)) {
			utils_err("Destination exists and is not the same type as the source:\n\t%s\n",
				  entry->path);
			return EINVAL;
		}

		/* Sanity check: Make sure the destination is not immutable and warn the user */
		if(dst_info->stx_attributes & STATX_ATTR_IMMUTABLE) {
			utils_wrn("Destination is immutable, skipping update:\n\t%s\n", entry->path);
			return 0;
		}

		if (st->opts & E4B_OPT_FORCE_UPDATE)
			goto update_check_done;

		/* Do they have the same mtime and ctime ? If so nothing has changed
		 * since the last backup. This is a relatively safe check since in
		 * order to tweak ctime root access is needed (and if an attacker has
		 * root access there is nothing we can do). */
		if (timestamp_eq(&src_info->stx_mtime, &dst_info->stx_mtime) &&
		    timestamp_eq(&src_info->stx_ctime, &dst_info->stx_ctime))
			return 0;

		/* Size comparison only makes sense for regular files and symlinks */
		if ((S_ISLNK(src_info->stx_mode) || S_ISREG(src_info->stx_mode)) &&
		    (src_info->stx_size != dst_info->stx_size))
			goto update_check_done;

		/* Is the source older than the destination ? Warn the user and move on.
		 * This is not a safe check since mtime can be tweaked but at least the
		 * user will know about it. If the destination is modified it doesn't
		 * make sense to try and preserve metadata either, so we just skip
		 * the update and move on. Note that if this is a directory there is
		 * a chance a previous backup was interrupted and since we set mtimes
		 * at the end of the backup we didn't update the directory's mtime. In
		 * such cases the user is expected to use E4B_OPT_FORCE_UPDATE. */
		if (timestamp_lt(&src_info->stx_mtime, &dst_info->stx_mtime)) {
			utils_wrn("Source is older than the destination, skipping update:\n\t%s\n",
				  entry->path);
			return 0;
		}

		/* If this is a symlink, make sure both source and destination point to the
		 * same place. If not delete destination so that we re-create it. */
		if (S_ISLNK(src_info->stx_mode)) {
			if (!check_lnk_path_match(entry, st)) {
				ret = unlinkat(st->dst_dirfd, entry->path, 0);
				if (ret) {
					utils_wrn("Could not replace symlink at destination:\n\t%s\n",
						  entry->path);
					utils_wrn("unlinkat() failed: %s\n", strerror(errno));
					return errno;
				}
				dst_exists = false;
				goto update_check_done;
			}
		} else if (S_ISREG(src_info->stx_mode)) {
		/* We don't have a way of comparing inode data/attributes etc so we'll
		 * overwrite them anyway if needed, at this point we can only compare
		 * contents of files / symlinks, and prevent copying them as an optimization.
		 * The simple approach is to check if mtimes are the same, if not (since we
		 * checked if source is older than the destination above) the source will be
		 * newer than the destination and we need to update destination. However this
		 * check is unsafe because an attacker may tweak the file contents of the
		 * destination, keeping the same size (e.g. a file containing hashes, where
		 * some hashes are replaced) as well as the mtime, so we may end up keeping
		 * an insecure copy of the file on the backup. A safer approach is to compare
		 * source and destination, which may be faster than updating the file (writing
		 * in a storage device is usually slower than reading), but it has to be done
		 * in userspace so it's much worse. For now the E4B_OPT_FORCE_UPDATE makes more
		 * sense and will be faster than comparing the files, in the future I may use
		 * IMA measurements if available, which are done in-kernel and cached (and there
		 * is also work to extend NFSv4 so that we can hopefuly get measurements from
		 * the NFS server instead of having to read the file on the client), or something
		 * better (wouldn't it be great if we could use FS_IOC_MEASURE_VERITY without
		 * making it permanent and turn the file read-only ?). */
			if (timestamp_eq(&src_info->stx_mtime, &dst_info->stx_mtime))
				skip_copy = 1;
		}
	}
 update_check_done:

	/* Track hardlinks:
	 * Since we don't cross mountpoints when creating the list of sources,
	 * we only need to store the inode number for every source file with
	 * a link count higher than 1. If we see the same inode number at another
	 * source file, it means it was a hardlink to the first one (since they
	 * belong to the same filesystem/mountpoint), so instead of copying it
	 * to the destination again, replicate the harlink. If the destination
	 * exists don't attempt to re-create the hardlink. */
	if (st->opts & E4B_OPT_NO_HARDLINKS || dst_exists)
		goto skip_hardlinks;

	if ((S_ISLNK(src_info->stx_mode) || S_ISREG(src_info->stx_mode)) &&
	    src_info->stx_nlink > 1) {
		struct e4b_entry *existing_entry = NULL;
		uint64_t *key = (uint64_t*) &src_info->stx_ino;
		utils_dbg("Got file with multiple hardlinks: %s\n", entry->path);
		existing_entry = g_hash_table_lookup(st->hardlinks, key);
		if (!existing_entry)
			g_hash_table_insert(st->hardlinks, key, entry);
		else {
			utils_dbg("Got hardlink to existing source, re-creating it on destination:\n\t%s -> %s\n",
				  entry->path, existing_entry->path);
			ret = linkat(st->dst_dirfd, existing_entry->path, st->dst_dirfd, entry->path, 0);
			if (ret < 0) {
				utils_err("Error while creating hardlink:\n\t%s\n",
					  entry->path);
				utils_perr("linkat() failed");
				return errno;
			}
			return 0;
		}
	}

 skip_hardlinks:

	/* Set the apropriate flags for openat() depending on file type,
	 * and create anything that's not a regular file. */
	switch (src_info->stx_mode & S_IFMT) {
	case S_IFDIR:
		if (!dst_exists) {
			ret = mkdirat(st->dst_dirfd, entry->path, src_info->stx_mode);
			if (ret) {
				utils_err("Error while creating subdirectory:\n\t%s\n",
					  entry->path);
				utils_perr("mkdirat() failed");
				return errno;
			}
		}

		if (st->opts & E4B_OPT_NO_METADATA)
			return 0;

		/* ctime/mtime for the directory may change if we add files to it
		 * later on, add directories to a separate list, so that we can update
		 * their timestamps after we are done copying files. */
		st->subdirs = g_list_prepend(st->subdirs, (gpointer) entry);
		
		src_open_flags = O_DIRECTORY | O_NOFOLLOW | O_NOATIME | O_RDONLY;
		dst_open_flags = src_open_flags;
		break;
	case S_IFLNK:
		if (!dst_exists) {
			lnk_path = get_sanitized_lnk_path(entry, st);
			utils_dbg("New symlink: %s -> %s\n", entry->path, lnk_path);

			ret = symlinkat(lnk_path, st->dst_dirfd, entry->path);
			if (ret < 0) {
				utils_err("Error while creating symbolic link:\n\t%s -> %s\n",
					  entry->path, lnk_path);
				utils_perr("symlinkat() failed");
				free(lnk_path);
				return errno;
			}
			free(lnk_path);
		}

		if (st->opts & E4B_OPT_NO_METADATA)
			return 0;

		src_open_flags = O_PATH | O_NOFOLLOW;
		dst_open_flags = src_open_flags;
		break;
	case S_IFIFO:
	case S_IFSOCK:
		node_type = "(named pipe / socket)";
	case S_IFBLK:
	case S_IFCHR:
		if (st->opts & E4B_OPT_NO_SPECIAL)
			return 0;

		/* XXX: This is mostly untested ! */
		if (!dst_exists) {
			utils_dbg("Creating special file %s:\n\t%s\n", node_type,
				  entry->path);
			device_id = makedev(src_info->stx_rdev_major, src_info->stx_rdev_minor);
			ret = mknodat(st->dst_dirfd, entry->path, src_info->stx_mode, device_id);
			if (ret < 0) {
				utils_err("Error while creating special file:\n\t%s\n",
					  entry->path);
				utils_perr("mknodat() failed");
				return errno;
			}
		}

		if (st->opts & E4B_OPT_NO_METADATA)
			return 0;

		src_open_flags = O_PATH | O_NOFOLLOW;
		dst_open_flags = src_open_flags;
		break;
	default:
		src_open_flags = O_RDONLY | O_NOFOLLOW | O_NOATIME;
		dst_open_flags = O_WRONLY | O_CREAT;
		dst_open_flags |= (dst_exists) ? O_TRUNC : O_EXCL;
		break;
	}

	entry->src_fd = TEMP_FAILURE_RETRY(openat(st->src_dirfd, entry->path, src_open_flags, 0));
	if (entry->src_fd < 0) {
		utils_err("Error while processing source file:\n\t%s\n", entry->path);
		utils_perr("openat() failed for source file");
		return errno;
	}

	entry->dst_fd = TEMP_FAILURE_RETRY(openat(st->dst_dirfd, entry->path, dst_open_flags, S_IRWXU));
	if (entry->dst_fd < 0) {
		utils_err("Error while processing destination file:\n\t%s\n", entry->path);
		utils_perr("openat() failed for destination file");
		close(entry->src_fd);
		return errno;
	}

	/* The following calls are responsible for closing the descriptors we
	 * opened above. */
	if (S_ISREG(src_info->stx_mode) && !skip_copy) {
		ret = copy_data(entry);
		if (ret)
			return ret;
	}

	ret = copy_metadata(entry);
	if (ret)
		return ret;

	return 0;
}

int process_entries(struct e4b_state *st)
{
	GList *lptr = NULL;
	struct e4b_entry *eptr = NULL;
	int ret = 0;

	for (lptr = st->entries; lptr != NULL; lptr = lptr->next) {
		eptr = (struct e4b_entry *)lptr->data;
		utils_info("\033[FCurrent file: %s\033[0K\n", eptr->path);
		ret = process_entry(eptr);
		if (ret) {
			utils_dbg("process_entry() exited with %lu for %s\n",
				  ret, eptr->path);
			if (st->opts & E4B_OPT_KEEP_GOING)
				continue;
			return ret;
		}
		st->entries_processed++;
		utils_info("\r%i/%i", st->entries_processed, st->num_entries);
	}
	utils_info("\n");

	return 0;
}
