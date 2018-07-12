
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include "log.h"
#include "server.h"
#include "daemon.h"
#include "utils.h"
#include "config_file.h"

int
main(int argc, char *argv[])
{
	config_t *config  = malloc(sizeof(config_t));
	config->workers   = sysconf(_SC_NPROCESSORS_ONLN);
	config->sessions  = 1024;
	config->daemonize = 1;
	config->verbose   = 0;
	config->conf      = strdup("/etc/tls-server.conf");
	config->pid       = strdup("/run/tls-server.pid");
	config->uid       = strdup("tlsserver");
	config->gid       = strdup("tlsserver");

	config->certs.chain = strdup("/path-to-tls-certs/cert.pem");
	config->certs.key   = strdup("/path-to-tls-certs/key.pem");
	config->certs.ca    = strdup("/path-to-tls-certs/ca.pem");


	const char *PACKAGE = "server";
	config->log.type     = strdup("syslog");
	config->log.level    = strdup("info");
	config->log.facility = strdup("daemon");

	config->addr.sin_family      = AF_INET;
	config->addr.sin_port        = htons(3003);
	config->addr.sin_addr.s_addr = htonl(INADDR_ANY); // config via file
	struct option long_opts[] = {
		{ "help",             no_argument, NULL, 'h' },
		{ "verbose",          no_argument, NULL, 'v' },
		{ "foreground",       no_argument, NULL, 'F' },
		{ "config",     required_argument, NULL, 'c' },
		{ "pidfile",    required_argument, NULL, 'p' },
		{ "user",       required_argument, NULL, 'u' },
		{ "group",      required_argument, NULL, 'g' },
		{ 0, 0, 0, 0 },
	};
	for (;;) {
		int idx = 1;
		int c = getopt_long(argc, argv, "h?v+Fc:p:u:g:", long_opts, &idx);
		if (c == -1) break;

		switch (c) {
		case 'h':
		case '?':
			printf("%s v%s\n", "tls-server", "0.0.1");
			printf("Usage: %s [-h?Fv] [-c /path/to/config]\n"
			       "          [-u user] [-g group] [-p /path/to/pidfile\n\n",
			        "tls-server");

			printf("Option:\n");
			printf("  -?, -h, --help    show this help screen\n");
			printf("  -F, --foreground  don't daemonize, stay in foreground\n");
			printf("  -v, --verbose     increase debugging\n");

			printf("  -c, --config      file path containing the config\n");

			printf("  -p, --pidfile     where to store the pidfile\n");
			printf("  -u, --user        the user to run as\n");
			printf("  -g, --group       the group to run under\n\n");

			printf("See also: \n  %s\n", "https://github.com/dmolik/tls-server"); // PACKAGE_URL);

			exit(EXIT_SUCCESS);

		case 'v':
			config->verbose++;
			break;
		case 'F':
			config->daemonize = 0;
			break;
		case 'c':
			config->conf = strdup(optarg);
			break;
		case 'p':
			config->pid  = strdup(optarg);
			break;
		case 'u':
			config->uid  = strdup(optarg);
			break;
		case 'g':
			config->gid  = strdup(optarg);
			break;
		default:
			free(config);
			fprintf(stderr, "unhandled option flag %#02x\n", c);
			return 1;
		}
	}
	if (parse_config_file(config, config->conf) != 0) {
		fprintf(stderr, "failed to parse config file\n");
		exit(EXIT_FAILURE);
	}
	if (config->daemonize) {
		log_open(PACKAGE, config->log.facility);
		log_level(LOG_ERR + config->verbose, NULL);

		mode_t um = umask(0);
		if (daemonize(config->pid, config->uid, config->gid) != 0) {
			fprintf(stderr, "daemonization failed: (%i) %s\n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
		umask(um);
	} else {
		log_open(PACKAGE, "console");
		log_level(LOG_ERR + config->verbose, NULL);
		if (!freopen("/dev/null", "r", stdin))
			logger(LOG_WARNING, "failed to reopen stdin </dev/null: %s", strerror(errno));
	}

	if (serve(config) != 0) {
		logger(LOG_ERR, "Failed to start tls-server");
		exit(EXIT_FAILURE);
	}

	return 0;
}
