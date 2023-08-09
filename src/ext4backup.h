/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2022 Nick Kossifidis <mickflemm@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* For *at functions, nftw() */
#define _POSIX_C_SOURCE 200809L

/* For TEMP_FAILURE_RETRY,
 * AT_EMPTY_PATH,
 * statx,
 * O_NOATIME,
 * SEEK_HOLE,
 * SEEK_DATA,
 * copy_file_range,
 * FTW_ACTIONRETVAL */
#define _GNU_SOURCE

/* Use 64bit offsets / sizes for files */
#define _LARGEFILE64_SOURCE

/* Force off_t to be 64 bits */
#define _FILE_OFFSET_BITS 64

//#define DEBUG

#include <stdbool.h>	/* For bool */
#include <stdint.h>	/* For typed ints */
#include <time.h>	/* For struct timespec */
#include <stdarg.h>	/* For va_args */
#include <errno.h>	/* For errno */
#include <sys/statfs.h>	/* For struct statfs */
#include <sys/stat.h>	/* For struct statx */
#include <glib.h>	/* For GList/GHashtable */
#include <ext2fs/ext2fs.h>	/* For ext2_filsys */

/* Defined on include/uapi/linux/magic.h */
#define EXT4_SUPER_MAGIC 0xef53
/* Defined on include/linux/statfs.h */
#define ST_RDONLY 0x0001

#define VERSION "0.2"

#define XATTR_CONF_PATH	"/etc/xattr.conf"

struct e4b_state {
	char *src;
	int src_len;
	int src_dirfd;
	bool src_frozen;
	char *dst;
	int dst_len;
	int dst_dirfd;
	off_t data_len;
	off_t existing_data_len;
	uint32_t opts;
	int num_entries;
	int entries_processed;
	struct statfs src_fsinfo;
	struct statfs dst_fsinfo;
	GHashTable *existing;
	GList *entries;
	GList *subdirs;
	GList *immutables;
	GHashTable *hardlinks;
	GList *skip_xattr_patterns;
	GHashTable *unsupported_xattrs;
	ext2_filsys dst_fs;
	bool extfs_opened;
	bool src_xattrs_disabled;
	bool dst_xattrs_disabled;
};

enum e4b_opts {
	E4B_OPT_NONRECURSIVE	= 1,
	E4B_OPT_NO_DATA		= (1 << 1),
	E4B_OPT_NO_METADATA	= (1 << 2),
	E4B_OPT_NO_UPDATE	= (1 << 3),
	E4B_OPT_NO_HARDLINKS	= (1 << 4),
	E4B_OPT_NO_SPECIAL	= (1 << 5),
	E4B_OPT_NO_ATTRS	= (1 << 6),
	E4B_OPT_NO_IMMUTABLES	= (1 << 7),
	E4B_OPT_NO_FSFREEZE	= (1 << 8),
	E4B_OPT_NO_XATTRS	= (1 << 9),
	E4B_OPT_NO_ACL		= (1 << 10),
	E4B_OPT_IGNORE_NODUMP	= (1 << 11),
	E4B_OPT_EXT4_FSTIMES	= (1 << 12),
	E4B_OPT_FORCE_UPDATE	= (1 << 13),
	E4B_OPT_COPY_ENCRYPTED	= (1 << 14),
	E4B_OPT_KEEP_GOING	= (1 << 15),
	E4B_OPT_NO_SPACE_CHECK	= (1 << 16),
	E4B_OPT_PURGE_EXCESS	= (1 << 17),
	E4B_OPT_IGNORE_TARGET	= (1 << 18)
};

struct e4b_entry {
	struct e4b_state *st;
	int depth;
	int base;
	struct statx src_info;
	int src_fd;
	struct statx dst_info;
	int dst_fd;
	char *path;
};

/* Prototypes */

/* Print utilities */
void utils_ann(const char *fmt, ...);
void utils_info(const char *fmt, ...);
void utils_wrn(const char *fmt, ...);
void utils_err(const char *fmt, ...);
void utils_perr(const char *msg);
void utils_dbg(const char *fmt, ...);
void print_time(struct timespec *ts, bool debug);
const char *print_size(off_t bytes);

/* Path manipulation */
char *get_sanitized_lnk_path(struct e4b_entry *entry, struct e4b_state *st);

/* FS helpers / EXT4-related ctime/crtime manipulation */
int get_path_info(const char *path, int fd, struct statx *buf, bool may_not_exist);
char *get_lnk_path(struct e4b_entry *entry, struct e4b_state *st, int dst, int *pathlen);
int check_lnk_path_match(struct e4b_entry *entry, struct e4b_state *st);
int set_fs_freeze(char* path, bool freeze);
int update_ext4_fstimes(struct e4b_state *st);

/* Attributes handling (FS_*_FL flags) */
void copy_attrs(struct e4b_entry *entry);
int update_immutables(struct e4b_state *st);

/* Extended attributes handling */
int copy_xattrs(const char* src_fdpath, const char* dst_fdpath, struct e4b_entry *entry);
int fill_skip_xattr_patterns(struct e4b_state *st);

/* State init/free */
int init_state(const char* src_in, const char* dst_in, int opts, struct e4b_state **st);
void free_state(struct e4b_state *st);

/* Entry processing */
ssize_t copy_data(struct e4b_entry *entry);
int copy_metadata(struct e4b_entry *entry);
int update_subdirs(struct e4b_state *st);
int process_entries(struct e4b_state *st);

/* Purge excess files/directories on target */
int purge_excess(struct e4b_state *st);
