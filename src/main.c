/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2022 Nick Kossifidis <mickflemm@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
 
#include "ext4backup.h"
#include <stddef.h>	/* For NULL */
#include <unistd.h>	/* For geteuid() */
#include <getopt.h>	/* For getopt_long() */
#include <stdlib.h>	/* For free(), EXIT_SUCCESS/FAILURE */
#include <sys/capability.h> /* For handling capabilities */

void usage(const char *self)
{
	utils_ann("\t--== ext4backup version %s ==--\n\n", VERSION);

	utils_info("%s [OPTIONS] <source directory> <destination directory>\n\n", self);

	utils_info("Options:\n");
	utils_info("\t--non-recursive\tIgnore subdirectories\n");
	utils_info("\t--skip-data\tDo not copy file contents\n");
	utils_info("\t--skip-metadata\tDo not preserve file metadata\n");
	utils_info("\t\t\t(also sets --skip-attrs/xattrs/acl and ignores ext4-fstimes)\n");
	utils_info("\t--skip-updates\tDo not update existing files\n");
	utils_info("\t--no-hardlinks\tDo not attempt to preserve hardlinks on destination hierarchy\n");
	utils_info("\t--skip-special\tDo not copy special files (devices, sockets, fifos)\n");
	utils_info("\t--skip-attrs\tDo not preserve file attributes (see chattr(1))\n");
	utils_info("\t--no-immutables\tDo not preserve the immutable flag (see chattr(1))\n");
	utils_info("\t--no-fsfreeze\tDo not attempt to freeze filesystems\n");
	utils_info("\t--skip-xattrs\tDo not preserve extended file attributes (see xattr(7))\n");
	utils_info("\t--skip-acl\tDo not preserve \"POSIX\" ACLs (see acl(5))\n");
	utils_info("\t--ignore-nodump\tIgnore the NODUMP attribute (see chattr(5) option d) and copy marked files anyway\n");
	utils_info("\t--ext4-fstimes\tAttempt to preserve ctime/crtime on destination fs in case it's ext4\n");
	utils_info("\t--force-update\tAlways update files on destination if they exist\n");
	utils_info("\t--copy-encrypted\tAssume all encrypted files in source hierarchy are unlocked\n");
	utils_info("\t--keep-going\tContinue on failure instead of exiting\n");

	utils_info("\nNotes:\n");
	utils_info("* The programm will not cross filesystem boundaries, anything mounted on the source hierarchy will be ignored\n");
	utils_info("* If both skip-data/metadata are set, it will still create files/directories/symlinks/hardlinks\n");
	utils_info("  this may be useful in case you only want to preserve the hierarchy structure.\n");
	utils_info("* If you don't run this as root you'll need the following capabilities:\n");
	utils_info("\tCAP_CHOWN:\t\tFor preserving ownership on files you don't own\n");
	utils_info("\tCAP_DAC_OVERRIDE:\tFor accessing files you don't have permission to access\n");
	utils_info("\tCAP_FOWNER:\t\tFor setting ACL,atrs,xattrs etc and using O_NOATIME on files you don't own\n");
	utils_info("\tCAP_LINUX_IMMUTABLE:\tFor preserving the immutable flag (see chattr(1))\n");
	utils_info("\tCAP_MKNOD:\t\tFor creating special files on destination\n");
	utils_info("\tCAP_SYS_ADMIN:\t\tFor preserving trusted/system xattrs, using fsfreeze, using --ext4-fstimes etc\n");
	utils_info("\tCAP_SETFCAP:\t\tFor preserving file capabilities (security.capability xattr)\n");
	utils_info("  If the programm lacks needed capabilities (e.g. through fscaps) it will skip related features\n");
	utils_info("  and may also fail with EPERM, especialy if you attempt to access files you don't own.\n");
}

static const struct option options[] = {
	{"non-recursive",	no_argument, NULL, E4B_OPT_NONRECURSIVE},
	{"skip-data",		no_argument, NULL, E4B_OPT_NO_DATA},
	{"skip-metadata",	no_argument, NULL, E4B_OPT_NO_METADATA},
	{"skip-updates",	no_argument, NULL, E4B_OPT_NO_UPDATE},
	{"no-hardlinks",	no_argument, NULL, E4B_OPT_NO_HARDLINKS},
	{"skip-special",	no_argument, NULL, E4B_OPT_NO_SPECIAL},
	{"skip-attrs",		no_argument, NULL, E4B_OPT_NO_ATTRS},
	{"no-immutables",	no_argument, NULL, E4B_OPT_NO_IMMUTABLES},
	{"no-fsfreeze",		no_argument, NULL, E4B_OPT_NO_FSFREEZE},
	{"skip-xattrs",		no_argument, NULL, E4B_OPT_NO_XATTRS},
	{"skip-acl",		no_argument, NULL, E4B_OPT_NO_ACL},
	{"ignore-nodump",	no_argument, NULL, E4B_OPT_IGNORE_NODUMP},
	{"ext4-fstimes",	no_argument, NULL, E4B_OPT_EXT4_FSTIMES},
	{"force-update",	no_argument, NULL, E4B_OPT_FORCE_UPDATE},
	{"copy-encrypted",	no_argument, NULL, E4B_OPT_COPY_ENCRYPTED},
	{"keep-going",		no_argument, NULL, E4B_OPT_KEEP_GOING},
	{0,			0,	     0,	   0}
};

int main(int argc, char *argv[])
{
	struct e4b_state *st = NULL;
	cap_t caps = NULL;
	uid_t uid = geteuid();
	const cap_value_t cap_list[8] = {CAP_CHOWN,		/* For preserving ownership */
					CAP_DAC_OVERRIDE,	/* For ignoring file/directory permissions */
					CAP_FOWNER,		/* For setting ACL, attrs, xattrs etc and using O_NOATIME */
					CAP_LINUX_IMMUTABLE,	/* For preserving the immutable attribute */
					CAP_MKNOD,		/* For creating special files (devices/sockets) */
					CAP_SYS_ADMIN,		/* Don't like this but we need it for preserving
								 * trusted/security xattrs, freezing the fs etc. */
					CAP_SETFCAP,		/* Needed to preserve file caps (security.capability) */
					CAP_SETPCAP
					};
	cap_flag_value_t cap_val = CAP_CLEAR;
	char *src = NULL;
	char *dst = NULL;
	bool src_frozen = false;
	int opt_args = 0;
	int opts = 0;
	int ret = 0;

	if (argc == 1) {
		usage(argv[0]);
		exit(EXIT_SUCCESS);
	} else if (argc < 3) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	while(1) {
		ret = getopt_long(argc, argv, "", options, NULL);
		if (ret == -1)
			break;
		else if (ret == '?') {
			utils_err("Invalid arguments\n");
			usage(argv[0]);
			exit(EXIT_FAILURE);
		}
		opts |= ret;
		opt_args++;
	}

	if (opt_args <= argc - 3) {
		src = argv[opt_args + 1];
		dst = argv[opt_args + 2];
	} else {
		utils_err("Invalid arguments\n");
		usage(argv[0]);
		exit(EXIT_FAILURE);	
	}

	utils_ann("\t--== ext4backup version %s ==--\n\n", VERSION);

	/* Drop privileges if we are root */
	caps = cap_get_proc();
	if (uid == 0) {
		utils_dbg("Dropping privileges\n");
		if (!caps) {
			utils_err("Could not determine capabilities of running process\n");
			utils_err("Refusing to run with full privileges\n");
			utils_perr("cap_get_proc() failed");
			return EXIT_FAILURE;
		}
		cap_clear(caps);
		cap_set_flag(caps, CAP_PERMITTED, 8, cap_list, CAP_SET);
		cap_set_flag(caps, CAP_EFFECTIVE, 7, cap_list, CAP_SET);
		ret = cap_set_proc(caps);
		if (ret) {
			utils_err("Could not set capabilities of running process\n");
			utils_err("Refusing to run with full privileges\n");
			utils_perr("cap_set_proc() failed");
			cap_free(caps);
			return EXIT_FAILURE;
		}
		cap_free(caps);
	} else {
		/* Check for needed privileges if we are not, warn the user and adapt opts
		 * as needed */

		cap_get_flag(caps, CAP_CHOWN, CAP_EFFECTIVE, &cap_val);
		if (cap_val == CAP_CLEAR) {
			utils_wrn("\n* CAP_CHOWN not available\n");
			utils_wrn("will not be able to preserve ownership for files not owned by us\n");
		}
		
		cap_get_flag(caps, CAP_DAC_OVERRIDE, CAP_EFFECTIVE, &cap_val);
		if (cap_val == CAP_CLEAR) {
			utils_wrn("\n* CAP_DAC_OVERRIDE not available\n");
			utils_wrn("will not be able to bypass permission checks when accessing files not owned by us\n");
		}
		
		/* Note: Even if we hanlded O_NOATIME for files not owned by the user, it's also
		 * impossible to set attrs,xattrs etc and checking uids all the time will complicate
		 * the code, leave it like this for now. */
		cap_get_flag(caps, CAP_FOWNER, CAP_EFFECTIVE, &cap_val);
		if (cap_val == CAP_CLEAR) {
			utils_wrn("\n* CAP_FOWNER not available\n");
			utils_wrn("will not be able to process files not owned by us\n");
		}
		
		cap_get_flag(caps, CAP_LINUX_IMMUTABLE, CAP_EFFECTIVE, &cap_val);
		if (cap_val == CAP_CLEAR && !(opts & E4B_OPT_NO_IMMUTABLES)) {
			utils_wrn("\n* CAP_LINUX_IMMUTABLE not available\n");
			utils_wrn("will not preserve the immutable flag\n");
			opts |= E4B_OPT_NO_IMMUTABLES;
		}
		
		cap_get_flag(caps, CAP_MKNOD, CAP_EFFECTIVE, &cap_val);
		if (cap_val == CAP_CLEAR && !(opts & E4B_OPT_NO_SPECIAL)) {
			utils_wrn("\n* CAP_MKNOD not available\n");
			utils_wrn("will not create special files\n");
			opts |= E4B_OPT_NO_SPECIAL;
		}

		cap_get_flag(caps, CAP_SYS_ADMIN, CAP_EFFECTIVE, &cap_val);
		if (cap_val == CAP_CLEAR) {
			utils_wrn("\n* CAP_SYS_ADMIN not available\n");
			utils_wrn("will not be able to preserve trusted/system/security xattrs\n");
			if (!(opts & E4B_OPT_NO_FSFREEZE)) {
				utils_wrn("will not be able to freeze filesystems\n");
				opts |= E4B_OPT_NO_FSFREEZE;
			}
			if (opts & E4B_OPT_EXT4_FSTIMES) {
				utils_wrn("will not be able to preserve ctime/crtime\n");
			}
		}

		cap_get_flag(caps, CAP_SETFCAP, CAP_EFFECTIVE, &cap_val);
		if (cap_val == CAP_CLEAR) {
			utils_wrn("\n* CAP_SETFCAP not available\n");
			utils_wrn("will not be able to preserve filecaps\n");
		}
	}

	/* Gather the list of files to copy, optionaly freezing the fs while at it */
	ret = init_state(src, dst, opts, &st);
	if (ret)
		goto cleanup;

	/* Process entries */
	ret = process_entries(st);
	if (ret)
		goto cleanup;

	/* We are done with reading from source, unfreeze it */
	if (src_frozen) {
		ret = set_fs_freeze(st->src, 0);
		if (ret) {
			utils_err("Could not unfreeze source fs, run fsfreeze manualy to recover !\n");
		} else
			st->src_frozen = false;
	}
	
	ret = update_subdirs(st);
	if (ret)
		goto cleanup;
	
	ret = update_immutables(st);
	if (ret)
		goto cleanup;

	ret = update_ext4_fstimes(st);
	if (ret)
		goto cleanup;

	ret = 0;

 cleanup:
	if (st)
		free_state(st);
	if (ret)
		exit(EXIT_FAILURE);

	return EXIT_SUCCESS;
}
