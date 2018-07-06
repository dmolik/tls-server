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
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include <fcntl.h>
#include <assert.h>
#include <errno.h>


int cleanenv(int n, const char **keep)
{
	extern char **environ;
	/* clean up the environment */
	int i, j;
	for (i = 0; environ[i]; i++) {
		int skip = 0;
		for (j = 0; j < n; j++) {
			size_t len = strlen(keep[j]);
			if (strncmp(environ[i], keep[j], len) == 0
			 && environ[i][len] == '=') {
				skip = 1;
				break;
			}
		}

		if (skip)
			continue;

		char *equals = strchr(environ[i], '=');
		char *name = calloc(equals - environ[i] + 1, sizeof(char));
		memcpy(name, environ[i], equals - environ[i]);
		unsetenv(name);
		free(name);
	}
	return 0;
}

int daemonize(const char *pidfile, const char *user, const char *group)
{
	umask(0);

	int rc, n;
	int fd = -1;
	if (pidfile) {
		fd = open(pidfile, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
		if (fd == -1) {
			perror(pidfile);
			exit(2);
		}
	}

	errno=0;
	struct passwd *pw = getpwnam(user);
	if (!pw) {
		fprintf(stderr, "Failed to look up user '%s': %s\n",
				user, (errno == 0 ? "user not found" : strerror(errno)));
		exit(2);
	}

	errno = 0;
	struct group  *gr = getgrnam(group);
	if (!gr) {
		fprintf(stderr, "Failed to look up group '%s': %s\n",
				group, (errno == 0 ? "group not found" : strerror(errno)));
		exit(2);
	}

	/* clean up the environment */
	const char *keepers[] = { "LANG", "SHLVL", "_", "PATH", "SHELL", "TERM" };
	rc = cleanenv(6, keepers);
	assert(rc == 0);

	setenv("PWD",     "/",                           1);
	setenv("HOME",    pw->pw_dir,                    1);
	setenv("LOGNAME", pw->pw_name,                   1);
	setenv("USER",    pw->pw_name,                   1);

	/* chdir to fs root to avoid tying up mountpoints */
	rc = chdir("/");
	assert(rc == 0);

	/* child -> parent error communication pipe */
	int pfds[2];
	rc = pipe(pfds);
	assert(rc == 0);

	/* fork */
	pid_t pid = fork();
	assert(pid >= 0);

	if (pid > 0) {
		close(pfds[1]);
		char buf[8192];
		while ( (n = read(pfds[0], buf, 8192)) > 0) {
			buf[n] = '\0';
			fprintf(stderr, "%s", buf);
		}
		exit(0);
	}
	close(pfds[0]);
	char error[8192];

	if (pidfile) {
		struct flock lock;
		int n;

		lock.l_type   = F_WRLCK;
		lock.l_whence = SEEK_SET;
		lock.l_start  = 0;
		lock.l_len    = 0; /* whole file */

		rc = fcntl(fd, F_SETLK, &lock);
		if (rc == -1) {
			snprintf(error, 8192, "Failed to acquire lock on %s.%s\n",
					pidfile,
					(errno == EACCES || errno == EAGAIN
						? "  Is another copy running?"
						: strerror(errno)));
			n = write(pfds[1], error, strlen(error));
			if (n < 0)
				perror("failed to inform parent of our error condition");
			if (n < (int) strlen(error))
				fprintf(stderr, "child->parent inform - only wrote %li of %li bytes\n",
					(long)n, (long)strlen(error));
			exit(2);
		}
	}

	/* leave session group, lose the controlling term */
	rc = (int)setsid();
	assert(rc != -1);

	if (pidfile) {
		/* write the pid file */
		char buf[8];
		snprintf(buf, 8, "%i\n", getpid());
		n = write(fd, buf, strlen(buf));
		if (n < 0)
			perror("failed to write PID to pidfile");
		if (n < (int)strlen(buf))
			fprintf(stderr, "only wrote %li of %li bytes to pidfile\n",
				(long)n, (long)strlen(error));
		rc = fsync(fd);
		assert(rc == 0);

		if (getuid() == 0) {
			/* chmod the pidfile, so it can be removed */
			rc = fchown(fd, pw->pw_uid, gr->gr_gid);
			assert(rc == 0);
		}
	}

	if (getuid() == 0) {
		/* set UID/GID */
		if (gr->gr_gid != getgid()) {
			rc = setgid(gr->gr_gid);
			assert(rc == 0);
		}
		if (pw->pw_uid != getuid()) {
			rc = setuid(pw->pw_uid);
			assert(rc == 0);
		}
	}

	/* redirect standard IO streams to/from /dev/null */
	if (!freopen("/dev/null", "r", stdin))
		perror("Failed to reopen stdin </dev/null");
	if (!freopen("/dev/null", "w", stdout))
		perror("Failed to reopen stdout >/dev/null");
	if (!freopen("/dev/null", "w", stderr))
		perror("Failed to reopen stderr >/dev/null");
	close(pfds[1]);

	return 0;
}
