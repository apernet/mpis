#ifndef MPIS_LOG_H
#define MPIS_LOG_H
#include <stdio.h>
#ifdef MPIS_DEBUG
#define log_debug(fmt, ...) log("DEBUG", fmt, ## __VA_ARGS__)
#else
#define log_debug(fmt, ...)
#endif
#define log_info(fmt, ...) log("INFO ", fmt, ## __VA_ARGS__)
#define log_notice(fmt, ...) log("NOTE ", fmt, ## __VA_ARGS__)
#define log_warn(fmt, ...) log("WARN ", fmt, ## __VA_ARGS__)
#define log_error(fmt, ...) log("ERROR", fmt, ## __VA_ARGS__)
#define log_fatal(fmt, ...) log("FATAL", fmt, ## __VA_ARGS__)
#define log(log_level, fmt, ...) fprintf(stderr, "[" log_level "] %s:%d %s: " fmt, __FILE__, __LINE__, __FUNCTION__, ## __VA_ARGS__)
#endif // MPIS_LOG_H