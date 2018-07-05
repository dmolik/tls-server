/*
  Copyright 2016 James Hunt <james@jameshunt.us>

  This file is part of libvigor.

  libvigor is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  libvigor is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with libvigor.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include <assert.h>
#include <errno.h>

#include <syslog.h>
#include "log.h"

void log_open(const char *ident, const char *facility)
{
	assert(ident);
	assert(facility);

	free(LIBVIGOR_LOG.ident);
	LIBVIGOR_LOG.ident = strdup(ident);
	assert(LIBVIGOR_LOG.ident);

	if (strcmp(facility, "stdout") == 0) {
		LIBVIGOR_LOG.console = stdout;
		return;
	}
	if (strcmp(facility, "stderr")  == 0
	 || strcmp(facility, "console") == 0) {
		LIBVIGOR_LOG.console = stderr;
		return;
	}

	if (strncmp(facility, "file:", 5) == 0) {
		char *path = strchr(facility, ':'); path++;
		LIBVIGOR_LOG.console = fopen(path, "w+");
		return;
	}

	int fac = strcmp(facility, "local0") == 0 ? LOG_LOCAL0
	        : strcmp(facility, "local1") == 0 ? LOG_LOCAL1
	        : strcmp(facility, "local2") == 0 ? LOG_LOCAL2
	        : strcmp(facility, "local3") == 0 ? LOG_LOCAL3
	        : strcmp(facility, "local4") == 0 ? LOG_LOCAL4
	        : strcmp(facility, "local5") == 0 ? LOG_LOCAL5
	        : strcmp(facility, "local6") == 0 ? LOG_LOCAL6
	        : strcmp(facility, "local7") == 0 ? LOG_LOCAL7
	        :                                   LOG_DAEMON;

	LIBVIGOR_LOG.console = NULL;
	closelog();
	openlog(LIBVIGOR_LOG.ident, LOG_PID, fac);
}

void log_close(void)
{
	if (LIBVIGOR_LOG.console) {
		fclose(LIBVIGOR_LOG.console);
		LIBVIGOR_LOG.console = NULL;
	} else {
		closelog();
	}

	free(LIBVIGOR_LOG.ident);
	LIBVIGOR_LOG.ident = NULL;
}

int log_level(int level, const char *name)
{
	int was = LIBVIGOR_LOG.level;
	if (name) {
		level = log_level_number(name);
		if (level < 0) level = LIBVIGOR_LOG.level;
	}
	if (level >= 0) {
		if (level > LOG_DEBUG)
			level = LOG_DEBUG;
		LIBVIGOR_LOG.level = level;
	}
	return was;
}

const char* log_level_name(int level)
{
	if (level < 0) level = LIBVIGOR_LOG.level;
	switch (level) {
	case LOG_EMERG:   return "emergency";
	case LOG_ALERT:   return "alert";
	case LOG_CRIT:    return "critical";
	case LOG_ERR:     return "error";
	case LOG_WARNING: return "warning";
	case LOG_NOTICE:  return "notice";
	case LOG_INFO:    return "info";
	case LOG_DEBUG:   return "debug";
	default:          return "UNKNOWN";
	}
}

int log_level_number(const char *name)
{
	if (!name) return -1;
	return   strcmp(name, "emerg")     == 0 ? LOG_EMERG
	       : strcmp(name, "emergency") == 0 ? LOG_EMERG
	       : strcmp(name, "alert")     == 0 ? LOG_ALERT
	       : strcmp(name, "crit")      == 0 ? LOG_CRIT
	       : strcmp(name, "critical")  == 0 ? LOG_CRIT
	       : strcmp(name, "err")       == 0 ? LOG_ERR
	       : strcmp(name, "error")     == 0 ? LOG_ERR
	       : strcmp(name, "warn")      == 0 ? LOG_WARNING
	       : strcmp(name, "warning")   == 0 ? LOG_WARNING
	       : strcmp(name, "notice")    == 0 ? LOG_NOTICE
	       : strcmp(name, "info")      == 0 ? LOG_INFO
	       : strcmp(name, "debug")     == 0 ? LOG_DEBUG
	       : -1;
}

void logger(int level, const char *fmt, ...)
{
	if (level > LIBVIGOR_LOG.level)
		return;

	va_list ap1, ap2;
	va_start(ap1, fmt);
	va_copy(ap2, ap1);
	size_t n = vsnprintf(NULL, 0, fmt, ap1);
	assert(n >= 0);
	va_end(ap1);

	char *msg = calloc(n + 1, sizeof(char));
	assert(msg);
	vsnprintf(msg, n + 1, fmt, ap2);
	msg[n] = '\0';
	va_end(ap2);

	if (LIBVIGOR_LOG.console) {
		assert(level >= 0 && level <= LOG_DEBUG);

		pid_t pid = getpid();
		assert(pid);

		fprintf(LIBVIGOR_LOG.console, "%s[%i] %s\n",
				LIBVIGOR_LOG.ident, pid, msg);
		fflush(LIBVIGOR_LOG.console);
	} else {
		syslog(level, "%s", msg);
	}
	free(msg);
}
