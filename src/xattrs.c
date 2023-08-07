/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2022 Nick Kossifidis <mickflemm@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ext4backup.h"
#include <stddef.h>	/* For NULL, size_t */
#include <string.h>	/* For strspn(), strcspn(), strndup(), strncmp(), strchr() */
#include <stdlib.h>	/* For realloc(), free() */
#include <fnmatch.h>	/* For fnmatch() */
#include <errno.h>	/* For error codes */
#include <sys/mman.h>	/* For mmap()/munmap() */
#include <fcntl.h>	/* For open() and O_* flags */
#include <sys/stat.h>	/* For S_* flags */
#include <sys/xattr.h>	/* For xattrs handling */
#include <acl/libacl.h>	/* For ACL handling */

/*****************\
* XATTRS HANDLING *
\*****************/

/*
 * Extended attributes (xattr(7)) include:
 *
 * "POSIX" ACLs (acl(7)): system.posix_acl_access/default
 * NFSv4 ACLs (honored by the nfs client): system.nfs4acl/nfs4_acl
 * Inline-data (ext4(5)): system.data
 * Per-file capabilities (capabilities(7)): security.capability
 * SELinux file contexts: security.selinux/security.sehash
 * AppArmor labels (apparmor_xattrs(7)): e.g. security.apparmor
 * SMACK attributes: security.SMACK64*
 * Integrity measurement: security.evm/security.ima
 * Privileged userspace stuff: trusted.*
 * Unprivileged userspace stuff: user.*
 * and more...
 *
 * Access control to various xattr namespaces are controlled by
 * the kernel, so for example we need CAP_SYS_ADMIN to be able
 * to set trusted/security xattrs, CAP_FOWNER to set acls etc.
 * Some xattrs are fs-specific and should not be preserved,
 * there is a list of xattrs to skip on /etc/xattrs.conf for
 * reference. The code here aims to be as generic as possible
 * and only handling ACLs differently in case the target FS
 * doesn't support ACLs and we need to preserve some equivalent
 * set of permissions. Other than that it's straight forward.
 */

/* Read /etc/xattrs.conf and populate the list of
 * xattr key patterns to skip. */
int fill_skip_xattr_patterns(struct e4b_state *st)
{
	int conf_fd = 0;
	int ret = 0;
	struct stat conf_fdinfo = { 0 };
	char *conf_data = NULL;
	char *text_ptr = NULL;
	char *pattern = NULL;
	size_t text_len = 0;

	if (st->opts & E4B_OPT_NO_XATTRS)
		return 0;

	conf_fd = open(XATTR_CONF_PATH, O_RDONLY);
	if (conf_fd < 0) {
		perror("open() failed");
		return errno;
	}

	if (fstat(conf_fd, &conf_fdinfo)) {
		perror("fstat() failed");
		return errno;
	}

	conf_data = mmap(NULL, conf_fdinfo.st_size, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE, conf_fd, 0);
	if (!conf_data) {
		close(conf_fd);
		perror("mmap() failed");
		return errno;
	}
	close(conf_fd);

	text_ptr = conf_data;

	do {
		/* Skip whitespace */
		text_ptr += strspn(text_ptr, " \t\n");
		/* Length of next text segment */
		text_len = strcspn(text_ptr, " \t\n#");

		/* If we get a # at the begining of a line,
		 * skip it. */
		if (text_ptr[text_len] == '#') {
			if (text_len) {
				ret = EINVAL;
				goto cleanup;
			}
			text_ptr += strcspn(text_ptr, "\n");
			continue;
			/* Did we reach the end of the text ? */
		} else if (text_ptr[text_len] == '\0')
			break;

		/* First text segment is the name pattern */
		pattern = strndup(text_ptr, text_len);

		/* Second text segment is the action */
		text_ptr += text_len;
		text_ptr += strspn(text_ptr, " \t\n");
		text_len = strcspn(text_ptr, " \t\n#");
		if (text_len == 4 && !strncmp(text_ptr, "skip", 4)) {
			st->skip_xattr_patterns = g_list_prepend(st->skip_xattr_patterns,
								(gpointer) pattern);
			utils_dbg("SKIP: %s\n", pattern);
		} else if (text_len == 11 && !strncmp(text_ptr, "permissions", 11)) {
			utils_dbg("PERMISSIONS: %s\n", pattern);
			free(pattern);
		} else {
			free(pattern);
			ret = EINVAL;
			goto cleanup;
		}

		text_ptr += text_len;
		/* There shouldn't be a third text segment unless it's a comment
		 * so the next non-whitespace character should be #, \n or \0 */
		text_ptr += strspn(text_ptr, " \t");
		if (text_ptr[0] != '#' && text_ptr[0] != '\n'
		    && text_ptr[0] != '\0') {
			free(pattern);
			ret = EINVAL;
			goto cleanup;
		}

		text_ptr += strspn(text_ptr, " \n");
	} while (text_ptr[0] != '\0');

 cleanup:
	munmap(conf_data, conf_fdinfo.st_size);
	return ret;
}

/* This checks both the skip patterns we created above from /etc/xattrs.conf
 * and the unsupported xattrs set we create as we go on copy_metadata() */
static int filter_xatrr_key(char *key, struct e4b_state *st)
{
	unsigned int num_elements = g_list_length(st->skip_xattr_patterns);
	char *pattern = NULL;
	char *match = NULL;
	int ret = 0;

	/* Check if this is a file with inline-data, in which case the file's data
	 * are stored as system.data xattr, which we should skip (we won't be able
	 * to set it anyway). */
	if (!strncmp(key, "system.data", 12))
		return 1;

	/* Check if key is in the unsupported set
	 * Note: man page says that we 'll get ENOTSUP if the namespace prefix
	 * is invalid but that doesn't mean it's invalid for any key, e.g. we
	 * may get ENOTSUP for system.posix_acl* if "POSIX" ACLs are not supported
	 * but that doesn't mean we can't still copy e.g. system.nfs4* xattrs. So
	 * we use the full key name when adding / checking keys using the hash table. */
	match = g_hash_table_lookup(st->unsupported_xattrs, key);
	if (match) {
		utils_dbg("Key in unsupported set: %s\n", key);
		return 1;
	}

	/* Check if key is marked with "skip" in /etc/xattr.conf */
	while (num_elements > 0) {
		pattern = g_list_nth_data(st->skip_xattr_patterns, --num_elements);
		utils_dbg("key: %s, pattern: %s\n", key, pattern);
		ret = fnmatch(pattern, key, 0);
		if (ret && ret != FNM_NOMATCH) {
			utils_err("Error while checking xattr pattern (%i)\n",
				  key);
			return ret;
		} else if (ret == FNM_NOMATCH)
			continue;
		else {
			utils_dbg("Key in skip set: %s\n", key);
			return 1;
		}
	}

	return 0;
}

/* Even if the target fs doesn't handle xattrs we still need to handle "POSIX"
 * ACLs (stored as xattrs) so that the file at the target fs has similar permissions
 * as the source. If both source and target fs support ACLs we won't reach this function
 * and we'll just copy the posix_acl xattrs. */
static int handle_unsupported_xattr(char *key, int *acl_done, const char *src_fdpath,
				    struct e4b_entry *entry)
{
	struct statx *src_info = &entry->src_info;
	struct e4b_state *st = entry->st;
	acl_t src_acl = {0};
	acl_entry_t acl_entry = {0};
	acl_tag_t tag_type = {0};
	acl_permset_t permset = {0};
	int entry_id = 0;
	int ret = 0;

	/* We only handle "POSIX" ACLs, the rest we just add them to the ignore set */
	if (strncmp(key, "system.posix_acl_access", 23) &&
	    strncmp(key, "system.posix_acl_default", 24)) {
		g_hash_table_add(st->unsupported_xattrs, key);
		utils_wrn("Adding xattr key to unsupported set: %s\n", key);
		return 0;
	}

	if (st->opts & E4B_OPT_NO_ACL)
		return 0;

	/* We may have multiple system.posix_acl* xattrs, we already handled ACLs, no need to process again  */
	if (*acl_done)
		return 0;

	/* We only care about ACL_TYPE_ACCESS, default ACLs don't mean anything if ACLs are not supported */
	src_acl = acl_get_file(src_fdpath, ACL_TYPE_ACCESS);
	if (!src_acl) {
		if (errno == ENOSYS || errno == ENOTSUP) {
			/* That's weird we have the attribute there but ACLs are not supported
			 * at the source fs, add them to the unsupported set since the mode bits
			 * are used anyway. XXX: Is this even possible ? */
			utils_wrn("Source fs has posix_acl xattrs but doesn't support ACLs\n");
			utils_wrn("adding them to the unsupported set.\n");
			g_hash_table_add(st->unsupported_xattrs, "system.posix_acl_access");
			g_hash_table_add(st->unsupported_xattrs, "system.posix_acl_default");
			*acl_done = 1;
			return 0;
		} else {
			utils_err("Could not get ACL from file although ACL xattrs are present:\n\t%s\n",
				  entry->path);
			utils_perr("acl_get_file() failed");
			return errno;
		}
	}

	/* Check if the ACL is equivalent to the mode bits */
	ret = acl_equiv_mode(src_acl, NULL);
	if (ret < 0) {
		utils_err("Invalid ACLs for: %s\n", entry->path);
		utils_perr("acl_equiv_mode() failed");
		acl_free(src_acl);
		return errno;
	} else if (!ret) {
		acl_free(src_acl);
		*acl_done = 1;
		return 0;
	}

	/* We need to make sure that the mode bits we'll set on the target will not
	 * provide more permissions than in the source, look for an ACL_MASK entry
	 * and use it to mask out the group permissions on mode bits. */
	for (entry_id = ACL_FIRST_ENTRY;; entry_id = ACL_NEXT_ENTRY) {

		ret = acl_get_entry(src_acl, entry_id, &acl_entry);
		if (ret < 0) {
			utils_err("Could not get acl entry for: %s\n",
				  entry->path);
			utils_perr("acl_get_entry() failed");
			break;
		} else if (!ret)
			break;

		ret = acl_get_tag_type(acl_entry, &tag_type);
		if (ret < 0) {
			utils_err("Error while processing acl entry for: %s\n",
				  entry->path);
			utils_perr("acl_get_tag_type() failed");
			break;
		}

		if (tag_type != ACL_MASK)
			continue;

		/* Got an ACL_MASK entry, mask our ACL_READ/WRITE/EXECUTE group
		 * permissions if not present. */
		ret = acl_get_permset(acl_entry, &permset);
		if (ret < 0) {
			utils_err("Error while processing acl entry for: %s\n",
				  entry->path);
			utils_perr("acl_get_permset() failed");
			break;
		}

		ret = acl_get_perm(permset, ACL_READ);
		if (ret < 0) {
			utils_err("Error while processing acl entry for: %s\n",
				  entry->path);
			utils_perr("acl_get_perm() failed");
			break;
		} else if (!ret)
			src_info->stx_mode &= ~S_IRGRP;

		ret = acl_get_perm(permset, ACL_WRITE);
		if (ret < 0) {
			utils_err("Error while processing acl entry for: %s\n",
				  entry->path);
			utils_perr("acl_get_perm() failed");
			break;
		} else if (!ret)
			src_info->stx_mode &= ~S_IWGRP;

		ret = acl_get_perm(permset, ACL_EXECUTE);
		if (ret < 0) {
			utils_err("Error while processing acl entry for: %s\n",
				  entry->path);
			utils_perr("acl_get_perm() failed");
			break;
		} else if (!ret)
			src_info->stx_mode &= ~S_IXGRP;

		break;
	}

	acl_free(src_acl);
	*acl_done = 1;
	return 0;
}

int copy_xattrs(const char* src_fdpath, const char* dst_fdpath, struct e4b_entry *entry)
{
	struct e4b_state *st = entry->st;
	ssize_t xattr_buf_size = 0;
	char *xattr_buf = NULL;
	char *xattr_buf_end = NULL;
	char *key = NULL;
	char *val = NULL;
	ssize_t val_len = 0;
	int acl_done = 0;
	int ret = 0;

	if (st->opts & E4B_OPT_NO_XATTRS)
		return 0;

	/* We tried getting xattrs from the source fs before and
	 * got ENOTSUP so don't bother trying again. */
	if (st->src_xattrs_disabled)
		return 0;

	/* Retrieve the buffer of xattr keys */
 xattr_buf_size_changed:
	xattr_buf_size = listxattr(src_fdpath, NULL, 0);
	utils_dbg("listxattr: %i\n", xattr_buf_size);
	if (xattr_buf_size < 0) {
		utils_err("Error while requesting list of xattrs for:\n\t%s\n",
			  entry->path);
		utils_perr("llistxattr() failed");
		return errno;
	} else if (!xattr_buf_size)
		return 0;

	xattr_buf = realloc(xattr_buf, ((size_t) xattr_buf_size) + 1);
	if (!xattr_buf) {
		utils_err("Error while allocating list of xattrs\n");
		utils_perr("malloc() failed");
		return errno;
	}

	xattr_buf_size = listxattr(src_fdpath, xattr_buf, ((size_t) xattr_buf_size));
	if (xattr_buf_size < 0) {
		if (errno == ERANGE) {
			utils_dbg("xattr buf size changed: %s\n", entry->path);
			goto xattr_buf_size_changed;
		}
		utils_err("Error while fetching list of xattrs\n");
		utils_perr("llistxattr() failed");
		ret = errno;
		goto cleanup;
	}

	xattr_buf[xattr_buf_size] = '\0';
	xattr_buf_end = xattr_buf + xattr_buf_size;

	/* Crawl the list of keys, fetch their values, and transfer them to target */
	for (key = xattr_buf; key != xattr_buf_end; key = strchr(key, '\0') + 1) {

		if (!*key || filter_xatrr_key(key, st))
			continue;

		utils_dbg("xattr key: %s\n", key);

 val_len_changed:
		val_len = getxattr(src_fdpath, key, NULL, 0);
		if (val_len < 0) {
			utils_err("Error while getting value for attribute (%s):\n\t%s\n",
				  key, entry->path);
			utils_perr("lgetxattr() failed");
			ret = errno;
			goto cleanup;
		} else if (val_len > 0) {
			val = realloc(val, val_len + 1);
			if (!val) {
				utils_err("Error while allocating value for attribute (%s):\n\t%s\n",
					  key, entry->path);
				utils_perr("realloc() failed");
				ret = errno;
				goto cleanup;
			}
			ret = getxattr(src_fdpath, key, val, val_len);
			if (ret < 0) {
				if (errno == ERANGE) {
					utils_dbg("xattr val len changed: %s\n", key);
					goto val_len_changed;
				}
				utils_err("Error while getting value for attribute (%s):\n\t%s\n",
					  key, entry->path);
				ret = errno;
				goto cleanup;
			}
			utils_dbg("got xattr val with len: %i\n", val_len);
		} /* Note: keys with zero-length values are ok */

		if (st->dst_xattrs_disabled) {
			ret = handle_unsupported_xattr(key, &acl_done, src_fdpath,
						       entry);
			if (ret)
				goto cleanup;
			continue;
		}

		ret = setxattr(dst_fdpath, key, val, val_len, 0);
		if (ret < 0) {
			if (errno == ENOTSUP || errno == ENOSYS || errno == EPERM) {
				ret = handle_unsupported_xattr(key, &acl_done, src_fdpath, entry);
				if (ret)
					goto cleanup;
			} else {
				utils_err("Error while setting xattr (%s) to:\n\t%s\n",
					   key, entry->path);
				utils_perr("lsetxattr() failed");
				ret = errno;
				goto cleanup;
			}
		}
	}

	ret = 0;

 cleanup:
 	if (xattr_buf)
 		free(xattr_buf);
 	if (val)
 		free(val);
 	return ret;
}
