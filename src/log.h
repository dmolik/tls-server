#ifndef _TLS_SERVER_LOG_H
#define _TLS_SERVER_LOG_H

#include <syslog.h>

void log_open(const char *ident, const char *facility);
void log_close(void);
void logger(int level, const char *fmt, ...);
int log_level_number(const char *name);
int log_level(int level, const char *name);

#endif
