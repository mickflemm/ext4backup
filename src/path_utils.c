/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2022 Nick Kossifidis <mickflemm@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ext4backup.h"
#include <stddef.h>	/* For NULL */
#include <string.h>	/* For strchr(), strncmp(), strnlen(), memmove(), memcpy() */
#include <stdlib.h>	/* For realloc() */
#include <unistd.h>	/* For readlinkat() */
#include <sys/param.h>	/* For MIN */

/*******************\
* PATH MANIPULATION *
\*******************/

static int get_common_prefix_depth(const char *path1, char *path2, int *len)
{
	/* Note that both path1 and path2 are malloced so they are
	 * aligned, we can start by comparing them word-by-word
	 * without worying about alignment. */
	unsigned long *al = (unsigned long *) path1;
	unsigned long *bl = (unsigned long *) path2;
	int minwords = *len / sizeof(unsigned long);
	int words = 0;
	int bytes = 0;
	int depth = 0;
	int len_to_last_component = 0;
	char saved = '\0';
	char *last_ptr = NULL;
	char *next_slash = NULL;

	while (al[words] == bl[words] && words < minwords)
		words++;

	bytes = words * sizeof(unsigned long);

	while (path1[bytes] == path2[bytes] && bytes < *len) {
		if (path1[bytes] == '/')
			len_to_last_component = bytes + 1;
		bytes++;
	}

	/* We reached the end of a path, so we got a full
	 * match, use the current index. */
	if ((path1[bytes] == '/' && path2[bytes] == '\0') ||
	    (path1[bytes] == '\0' && path2[bytes] == '/') ||
	    (path1[bytes] == '\0' && path2[bytes] == '\0')) {
		*len = bytes;
		last_ptr = path2 + bytes;
	/* If it's aligned to a component or a partial match
	 * (e.g. a/bc vs a/bd -> a/), use the length to the
	 * last component. */
	} else if (len_to_last_component) {
		*len = len_to_last_component;
		last_ptr = path2 + len_to_last_component;
	/* No common prefix found */
	} else {
		*len = 0;
		return 0;
	}

	/* Temporarily terminate path2 so that we can count the
	 * common prefix's depth. */
	saved = *last_ptr;
	*last_ptr = '\0';
	next_slash = strchr(path2, '/');
	while (next_slash != NULL) {
		depth++;
		next_slash = strchr(next_slash + 1, '/');
	}
	*last_ptr = saved;

	return depth;
}

char *get_lnk_path(struct e4b_entry *entry, struct e4b_state *st)
{
	char *lnk_path = NULL;
	int lnk_pathlen = 0;
	int tmp_lnk_pathlen = 64;
	int common_prefix_depth = 0;
	int common_prefix_len = 0;
	int back_steps = 0;
	char *tmp = NULL;
	char *relpath_str = NULL;
	int relpath_len = 0;

 retry:
	if (!lnk_path || lnk_pathlen != 0) {
		tmp = realloc(lnk_path, tmp_lnk_pathlen);
		if (!tmp) {
			utils_err("Could not allocate buffer for new symlink target\n");
			return NULL;
		} else
			lnk_path = tmp;
	}
	
	lnk_pathlen = readlinkat(st->src_dirfd, entry->path, lnk_path, tmp_lnk_pathlen);
	if (lnk_pathlen < 0) {
		utils_err("Could not get symlink contents for:\n\t%s\n", entry->path);
		utils_perr("readlink() failed");
		return NULL;
	}

	/* Did readlink truncate ? */
	if (lnk_pathlen == tmp_lnk_pathlen) {
		tmp_lnk_pathlen += 64;
		goto retry;
	}

	lnk_path[lnk_pathlen] = '\0';
	utils_dbg("Got symlink:\n\t%s -> %s\n", entry->path, lnk_path);

	/* In case we have an absolute symlink that points somewhere within
	 * the source hierarchy, recreating it as-is in the target
	 * hierarchy will make no sense because the absolute path there
	 * will be different. We have two options here, the simple approach
	 * would be to just swap the absolute path of the source with the
	 * absolute path of the target on the link path, but then if we mount
	 * the target hierarchy somewhere else the symlinks will again become
	 * unresolved. So we go for the second option which is to convert them
	 * to relative symlinks in the target hierarchy. For symlinks that are
	 * already relative or point somewhere outside the source hierarchy we
	 * don't care and recreate them as-is. */
	if (lnk_path[0] != '/' || strncmp(lnk_path, st->src, st->src_len))
		return lnk_path;

	/* Shift lnk_path to the left so that the source dir dissapears and
	 * we can compare it with entry->path, to get the relative path for
	 * the symlinki target. */
	lnk_path = memmove(lnk_path, lnk_path + (st->src_len + 1), lnk_pathlen - (st->src_len +1) + 1);
	lnk_pathlen = strnlen(lnk_path, lnk_pathlen);

	/* Note: entry->base is the length of entry->path's basename
	 * component, so it doesn't include the entry's filename. */
	common_prefix_len = MIN(entry->base, lnk_pathlen);
	common_prefix_depth = get_common_prefix_depth(entry->path, lnk_path, &common_prefix_len);

	/* We don't have a common path prefix, we need to go back to the root in order
	 * to reach lnk_path. Note that entry->depth includes the entry itself so
	 * we need -1 there to refer to its parent directory instead. */
	if (!common_prefix_len) {
		back_steps = (entry->depth - 1);
		relpath_str = lnk_path;
	/* The common prefix is entry->path's parent directory so we don't need
	 * to go back, the target is below the same directory as entry->path. */
	} else if (!common_prefix_depth) {
		back_steps = 0;
		relpath_str = lnk_path + common_prefix_len;
	/* Go back from entry->path's parent directory to the common prefix depth
	 * between entry->path and lnk_path. */
	} else {
		back_steps = (entry->depth - 1) - common_prefix_depth;
		relpath_str = lnk_path + common_prefix_len;
	}

	/* Count how many steps back we need to take and create a string with "../"
	 * for every step. We reuse the link_path buffer since even the smallest
	 * component "/a/" has the same len as "../" so we have enough space. */

	/* Special case: the symlink points to the last element
	 * of the common prefix which is a directory, so go one
	 * more step back. */
	if (relpath_str[0] == '\0')
		back_steps++;

	/* Move relpath inside lnk_path buffer to make room for the steps. */
	relpath_len = strnlen(relpath_str, lnk_pathlen);
	relpath_str = memmove(lnk_path + (back_steps * 3), relpath_str, relpath_len + 1);
	while (back_steps-- > 0) {
		relpath_str -= 3;
		memcpy(relpath_str, "../", 3);
	}

	return lnk_path;
}


