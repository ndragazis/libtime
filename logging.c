#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "logging.h"
#include "common.h"


const char *log_level_msg[NUM_LOG_LEVELS] =
{
	[INFO] = "INFO",
	[ERROR] = "ERROR",
	[DEBUG] = "DEBUG"
};

static struct {
	int   debug;
	FILE *logfd;
} log_ctx;

void setup_logging(int _debug, char *logfile) {
	FILE *logfd;

	if (_debug > 0)
		log_ctx.debug = 1;
	else
		log_ctx.debug = 0;

	/* Define output file descriptor for the logs. */
	if (logfile != NULL) {
		logfd = fopen(logfile, "w+");
		if (logfd == NULL) {
			fprintf(stderr, "Opening file '%s' for logging"
				" failed with %d (%s)\n",
				logfile, errno, strerror(errno));
			exit(1);
		}
	} else {
		/* Log to standard output. */
		logfd = stderr;
	}
	log_ctx.logfd = logfd;
}

void print_log(log_level level, const char *fmt, ...) {
	int ret;
	va_list args;
	char *new_fmt;
	int new_fmt_size;

	if (level == DEBUG && !log_ctx.debug)
		return;

	new_fmt_size = strlen(fmt) + 10;
	new_fmt = malloc(new_fmt_size);
	ret = snprintf(new_fmt, new_fmt_size, "[%s] %s", log_level_msg[level], fmt);
	ensure(ret < new_fmt_size);

 	va_start(args, fmt);
	vfprintf(log_ctx.logfd, new_fmt, args);
	va_end(args);
}
