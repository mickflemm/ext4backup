/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2022 Nick Kossifidis <mickflemm@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ext4backup.h"
#include <stddef.h>	/* For NULL, size_t */
#include <unistd.h>	/* For close(), lseek(), copy_file_range() */
#include <errno.h>	/* For error codes */
#include <sys/sendfile.h>	/* For sendfile() */

/***************\
* DATA TRANSFER *
\***************/

static ssize_t copy_data_chunk(int src_fd, int dst_fd, off_t offset, size_t len)
{
	static bool use_sendfile = false;
	off_t off_in = offset;
	off_t off_out = offset;
	off_t tmp_off = 0;
	ssize_t ret = 0;

	utils_dbg("copying %i bytes\n", len);

	if (use_sendfile)
		goto fallback;

	ret = copy_file_range(src_fd, &off_in, dst_fd, &off_out, len, 0);
	if (ret < 0 && errno != EXDEV) {
		utils_perr("copy_file_range() failed");
		return ret;
	} else if (ret < 0 && errno == EXDEV) {
		utils_wrn("copy_file_range() not supported for copies between source and target fs\n");
		utils_info("falling back to sendfile()\n");
		use_sendfile = true;
	} else
		return ret;

 fallback:
	/* sendfile() can send data to a socket as well, it won't use off_in for the
	 * target file, it'll start writing there from its current offset. To avoid that
	 * update the offset of the target file so that sendfile() copies from / to the
	 * same offset. */
	tmp_off = TEMP_FAILURE_RETRY(lseek(dst_fd, off_in, SEEK_SET));
	if (tmp_off == (off_t) -1) {
		utils_err("Could not sync target file's offset when using sendfile\n");
		utils_perr("lseek(SEEK_SET) failed");
		return -1;
	}
	ret = sendfile(dst_fd, src_fd, &off_in, len);
	if (ret < 0) {
		utils_perr("sendfile() failed");
	}

	return ret;
}

ssize_t copy_data(struct e4b_entry *entry)
{
	struct statx *src_info = &entry->src_info;
	int src_fd = entry->src_fd;
	int dst_fd = entry->dst_fd;
	off_t chunk_start = 0;
	off_t chunk_end = 0;
	size_t chunk_len = 0;
	off_t src_offt = 0;
	ssize_t ret = 0;

	utils_dbg("Copying %i bytes\n", src_info->stx_size);

	while (src_offt < src_info->stx_size) {
		/* Look for a data chunk */
		chunk_start = TEMP_FAILURE_RETRY(lseek(src_fd, src_offt, SEEK_DATA));
		if (chunk_start == (off_t) - 1) {
			/* Couldn't find next data chunk, file ends with a hole,
			 * truncate target file so that it has the correct size. */
			if (errno == ENXIO) {
				utils_dbg("No data chunk past current offset, truncating to end of file\n");
				src_offt = TEMP_FAILURE_RETRY(lseek(src_fd, 0, SEEK_END));
				if (src_offt < 0) {
					utils_err("Could not seek to the end of source: %s\n",
						  entry->path);
					utils_perr("lseek(SEEK_END) failed");
					ret = errno;
					goto cleanup;
				}
				utils_dbg("src_offt: %i, size: %i\n", src_offt,
					  src_info->stx_size);
				ret = TEMP_FAILURE_RETRY(ftruncate(dst_fd, src_offt));
				if (ret < 0) {
					utils_err("Could not truncate target: %s\n", entry->path);
					utils_perr("ftruncate() failed");
					ret = errno;
					goto cleanup;
				}
				ret = 0;
				goto cleanup;
			}
			utils_perr("could not lseek(SEEK_DATA)");
			ret = errno;
			goto cleanup;
		}

		/* Find out where the data chunk ends, SEEK_HOLE will give us either
		 * the next hole or the EOF. */
		chunk_end = TEMP_FAILURE_RETRY(lseek(src_fd, chunk_start, SEEK_HOLE));
		if (chunk_end == (off_t) - 1) {
			utils_perr("could not lseek(SEEK_HOLE)");
			ret = errno;
			goto cleanup;
		}

		/* Note: above calls to lseek have changed the offset of source file
		 * that's why we pass the offset of chunk_start to copy_data_chunk
		 * instead of letting it work from the current source offset. */

		chunk_len = chunk_end - chunk_start;

		/* Do in-kernel copy of data chunk to destination fd */
 again:
		ret = copy_data_chunk(src_fd, dst_fd, chunk_start, chunk_len);
		if (ret < 0) {
			ret = errno;
			goto cleanup;
		} else if (ret < chunk_len) {
			chunk_start += ret;
			chunk_len -= ret;
			goto again;
		}
		utils_dbg("copied %i bytes\n", ret);

		src_offt = chunk_end;
	}

	ret = 0;

 cleanup:
	if (ret) {
		close(src_fd);
		close(dst_fd);	
	}
	return ret;
}

