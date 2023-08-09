/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2023 Nick Kossifidis <mickflemm@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ext4backup.h"
#include <stddef.h>	/* For NULL */
#include <glib.h>	/* For GList/GHashtable */
#include <fcntl.h>	/* For AT_REMOVEDIR */
#include <unistd.h>	/* For unlinkat() */

int path_compare(const void* path1, const void* path2) {
	return strncmp((char*) path1, (char*) path2, PATH_MAX);
}

#ifdef DEBUG
static void print_excess(gpointer data, gpointer user_data)
{
	utils_dbg("Excess: %s\n", (char*) data);
}
#endif

static int failures = 0;

static void unlink_excess(gpointer data, gpointer user_data)
{
	struct e4b_state *st = (struct e4b_state*) user_data;
	struct statx *tmp = g_hash_table_lookup(st->existing, data);
	int ret = 0;

	if (tmp->stx_attributes & STATX_ATTR_IMMUTABLE) {
		utils_wrn("Won't try to purge immutable file on target: %s", data);
		return;
	} else if (tmp->stx_attributes & STATX_ATTR_VERITY) {
		utils_wrn("Won't try to purge file protected with verity: %s", data);
		return;
	}

	utils_dbg("Unlinking: %s\n", data);
	ret = unlinkat(st->dst_dirfd, (const char*) data, (tmp->stx_mode & S_IFDIR) ? AT_REMOVEDIR : 0);
	if (ret < 0) {
		utils_err("Could not delete %s\n\t%s\n", strerror(errno));
		failures++;
	}

}

int purge_excess(struct e4b_state *st)
{
	GList *sorted = NULL;

	if (!st->existing || !(st->opts & E4B_OPT_PURGE_EXCESS))
		return 0;

	sorted = g_hash_table_get_keys(st->existing);
	sorted = g_list_sort(sorted, path_compare);
	/* The above will result a list where directories come before their contents, where
	 * in our case we want to first delete their contents and then the directories, so
	 * reverse the list. */
	sorted = g_list_reverse(sorted);

#ifdef DEBUG
	g_list_foreach(sorted, print_excess, NULL);
#endif

	failures = 0;
	g_list_foreach(sorted, unlink_excess, st);

	/* Don't free the elements here, they are still owned by the hashtable */
	g_list_free(sorted);

	return failures;
}