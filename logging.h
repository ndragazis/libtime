#ifndef LOGGING_H
#define LOGGING_H

typedef enum {
	INFO = 0,
	ERROR,
	DEBUG,
	NUM_LOG_LEVELS
} log_level;

void setup_logging(int _debug, char *logfile);
void print_log(log_level level, const char *fmt, ...);


#define pr_log(level, fmt, ...) \
        (print_log(level, fmt, ##__VA_ARGS__))

#define pr_info(fmt, ...)  pr_log(INFO, fmt, ##__VA_ARGS__)
#define pr_error(fmt, ...) pr_log(ERROR, fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...) pr_log(DEBUG, fmt, ##__VA_ARGS__)

#endif  /* LOGGING_H */
