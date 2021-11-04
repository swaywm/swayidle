#ifndef _SWAYIDLE_LOG_H
#define _SWAYIDLE_LOG_H

#include <stdarg.h>
#include <string.h>
#include <errno.h>

enum log_importance {
    LOG_SILENT = 0,
    LOG_ERROR = 1,
    LOG_INFO = 2,
    LOG_DEBUG = 3,
    LOG_IMPORTANCE_LAST,
};

void swayidle_log_init(enum log_importance verbosity);

#ifdef __GNUC__
#define _ATTRIB_PRINTF(start, end) __attribute__((format(printf, start, end)))
#else
#define _ATTRIB_PRINTF(start, end)
#endif

void _swayidle_log(enum log_importance verbosity, const char *format, ...)
    _ATTRIB_PRINTF(2, 3);

const char *_swayidle_strip_path(const char *filepath);

#define swayidle_log(verb, fmt, ...) \
    _swayidle_log(verb, "[%s:%d] " fmt, _swayidle_strip_path(__FILE__), \
            __LINE__, ##__VA_ARGS__)

#define swayidle_log_errno(verb, fmt, ...) \
    swayidle_log(verb, fmt ": %s", ##__VA_ARGS__, strerror(errno))

#endif
