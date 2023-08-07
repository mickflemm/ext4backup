/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2022 Nick Kossifidis <mickflemm@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ext4backup.h"
#include <stdio.h>	/* For *printf() etc */
#include <string.h>	/* For strerror() */
#include <time.h>	/* For localtime_r(), tzset(), strftime() etc */

/****************\
* CONSOLE OUTPUT *
\****************/

/* Some codes for prety output on the terminal */
#define NORMAL	"\x1B[0m"
#define	BRIGHT	"\x1B[1m"
#define	DIM	"\x1B[2m"
#define RED	"\x1B[31m"
#define GREEN	"\x1B[32m"
#define YELLOW	"\x1B[33m"
#define BLUE	"\x1B[34m"
#define MAGENTA	"\x1B[35m"
#define CYAN	"\x1B[36m"
#define WHITE	"\x1B[37m"

void utils_ann(const char *fmt, ...)
{
	va_list args;

	printf(GREEN);
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	printf(NORMAL);
}

void utils_info(const char *fmt, ...)
{
	va_list args;

	printf(CYAN);
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	printf(NORMAL);
}

void utils_wrn(const char *fmt, ...)
{
	va_list args;

	fprintf(stderr, YELLOW);
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fprintf(stderr, NORMAL);
}

void utils_err(const char *fmt, ...)
{
	va_list args;

	fprintf(stderr, RED);
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fprintf(stderr, NORMAL);
}

void utils_perr(const char *msg)
{
	fprintf(stderr, RED);
	fprintf(stderr, "%s: %s\n", msg, strerror(errno));
	fprintf(stderr, NORMAL);
}

#ifdef DEBUG
void utils_dbg(const char *fmt, ...)
{
	va_list args;

	fprintf(stderr, MAGENTA);
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fprintf(stderr, NORMAL);
}

void print_time(struct timespec *ts, bool debug)
{
	struct tm t = {0};
	char timestr[64];
	static bool first = true;

	if (first) {
		tzset();
		first = false;
	}

	localtime_r(&(ts->tv_sec), &t);
	strftime(timestr, sizeof(timestr), "%F %T", &t);
	if (debug)
		utils_dbg("%s", timestr);
	else
		utils_info("%s", timestr);
}

#else
void utils_dbg( __attribute__((unused))
	       const char *fmt, ...) { }
void print_time(struct timespec *ts, bool debug) {}
#endif

const char *print_size(off_t bytes)
{
#define KB 1024.0
#define MB (KB * 1024.0)
#define GB (MB * 1024.0)
#define TB (GB * 1024.0)
	static char str[24] = { 0 };

	if (bytes >= TB)
		snprintf(str, 24, "%9.3f TiB", bytes / TB);
	else if (bytes >= GB)
		snprintf(str, 24, "%9.3f GiB", bytes / GB);
	else if (bytes >= MB)
		snprintf(str, 24, "%9.3f MiB", bytes / MB);
	else if (bytes >= KB)
		snprintf(str, 24, "%9.3f KiB", bytes / KB);
	else
		snprintf(str, 24, "%9lu B  ", bytes);
#undef TB
#undef GB
#undef MB
#undef KB
	return str;
}

