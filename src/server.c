#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include <fcntl.h>
#include <netinet/tcp.h>
#include <assert.h>
#include <errno.h>

#include <sys/epoll.h>
#include <sys/sysmacros.h>

#include <pthread.h>
#include <getopt.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "log.h"
#include "daemon.h"
#include "server.h"
#include "config_file.h"

typedef struct {
	int                 fd;
	unsigned int        starttime;
	SSL                *ssl;
	struct sockaddr_in  addr;
} peer_t;

typedef struct {
	int      peer_len;
	peer_t **peers;
} sessions_t;

typedef struct {
	int       fd;
	int       epollfd;
	SSL_CTX  *ctx;
} server_t;

config_t  *config;

typedef struct {
	int fd[2];
} pair_t;
typedef struct {
	int      len;
	pair_t **pairs;
} comm_t;
comm_t *intercom;

int
create_socket(void)
{
	int s;

	s = socket(config->addr.sin_family, SOCK_STREAM, 0);
	if (s < 0) {
		logger(LOG_ERR, "Unable to create socket (%i) %s", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	int opt = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const void*)&opt,
		sizeof(int));
	setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (const void*)&opt,
		sizeof(int));

	int fl = fcntl(s, F_GETFL);
	fcntl(s, F_SETFL, fl|O_NONBLOCK|O_ASYNC);

	if (bind(s, (struct sockaddr*)&(config->addr), sizeof(struct sockaddr_in)) < 0) {
		logger(LOG_ERR, "Unable to bind (%i) %s", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (listen(s, SOMAXCONN) < 0) {
		logger(LOG_ERR, "Unable to listen (%i) %s", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	return s;
}

void
init_openssl()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

void
cleanup_openssl()
{
	EVP_cleanup();
}

SSL_CTX *create_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;
	//FILE *fp;

	method = TLSv1_server_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		//logger(LOG_ERR, "Unable to create SSL context (%i) %s", errno, strerror(errno));
		//ERR_print_errors_fp(fp);
		//logger(LOG_ERR, "%s", fp);
		exit(EXIT_FAILURE);
	}

	return ctx;
}

void
configure_context(SSL_CTX *ctx)
{
	SSL_CTX_set_ecdh_auto(ctx, 1);
	const long flags = SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1|SSL_OP_NO_COMPRESSION;
	logger(LOG_DEBUG, "Setting TLS CTX flags");
	SSL_CTX_set_options(ctx, flags);
	const char *PREFERRED_CIPHERS =
		"kEECDH+ECDSA+AES256:EECDH+RSA+AES256+GCM+SHA384"
		":EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH"
		":HIGH:!aNULL:!eNULL:!EXPORT:!MD5:!RC4:!DES:!SSLv2"
		":!LOW:!CAMELLIA"; // this should probably be configurable
	SSL_CTX_set_cipher_list(ctx, PREFERRED_CIPHERS);

	logger(LOG_DEBUG, "loading cert chain file");
	if (SSL_CTX_use_certificate_chain_file(ctx, config->certs.chain) <= 0) {
		logger(LOG_ERR, "failed to load cert file(%s) [%s]",
			config->certs.chain, ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}

	logger(LOG_DEBUG, "loading key file");
	if (SSL_CTX_use_PrivateKey_file(ctx, config->certs.key, SSL_FILETYPE_PEM) <= 0 ) {
		logger(LOG_ERR, "failed to load key file(%s) [%s]",
			config->certs.key, ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}
}

int
add_client(server_t *server, sessions_t *sessions, struct sockaddr_in peer_addr, int peer_fd) {
	sessions->peers[sessions->peer_len]     = malloc(sizeof(peer_t));
	sessions->peers[sessions->peer_len]->fd = peer_fd;
	int fl = fcntl(sessions->peers[sessions->peer_len]->fd, F_GETFL);
	fcntl(sessions->peers[sessions->peer_len]->fd, F_SETFL, fl|O_NONBLOCK|O_ASYNC);

	int op =1;
	if (setsockopt(sessions->peers[sessions->peer_len]->fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&op, sizeof(op))) {
		logger(LOG_ERR, "setsocketopt(), SO_KEEPALIVE (%i) %s", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	op = 10;
	if (setsockopt(sessions->peers[sessions->peer_len]->fd, SOL_TCP, TCP_KEEPIDLE, (void *)&op, sizeof(op))) {
		logger(LOG_ERR, "setsocketopt(), SO_KEEPIDLE (%i) %s", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	op = 5;
	if (setsockopt(sessions->peers[sessions->peer_len]->fd, SOL_TCP, TCP_KEEPCNT, (void *)&op, sizeof(op))) {
		logger(LOG_ERR, "setsocketopt(), SO_KEEPCNT (%i) %s", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	op = 5;
	if (setsockopt(sessions->peers[sessions->peer_len]->fd, SOL_TCP, TCP_KEEPINTVL, (void *)&op, sizeof(op))) {
		logger(LOG_ERR, "setsocketopt(), SO_KEEPINTVAL (%i) %s", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	sessions->peers[sessions->peer_len]->addr = peer_addr;
	sessions->peers[sessions->peer_len]->ssl  = SSL_new(server->ctx);

	SSL_set_fd(sessions->peers[sessions->peer_len]->ssl,
		sessions->peers[sessions->peer_len]->fd);
	SSL_set_accept_state(sessions->peers[sessions->peer_len]->ssl);
	SSL_do_handshake(sessions->peers[sessions->peer_len]->ssl);

	struct epoll_event ev;
	ev.events = EPOLLIN|EPOLLET;
	ev.data.fd = sessions->peers[sessions->peer_len]->fd;
	if (epoll_ctl(server->epollfd, EPOLL_CTL_ADD, sessions->peers[sessions->peer_len]->fd, &ev) == -1) {
		logger(LOG_ERR, "failed to add peer socket to fd loop (%i) %s", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	logger(LOG_INFO, "Client connected from %s:%u\n", inet_ntoa(sessions->peers[sessions->peer_len]->addr.sin_addr),
		ntohs(sessions->peers[sessions->peer_len]->addr.sin_port));
	sessions->peer_len++;

	return 0;
}

int
delete_client(server_t *server, sessions_t *sessions, int p)
{
	SSL_shutdown(sessions->peers[p]->ssl);
	SSL_free(sessions->peers[p]->ssl);
	struct epoll_event ev;
	epoll_ctl(server->epollfd, EPOLL_CTL_DEL, sessions->peers[p]->fd, &ev);
	free(sessions->peers[p]);
	if (p < sessions->peer_len)
	for (int i = p; i < sessions->peer_len; i++)
		sessions->peers[i] = sessions->peers[i + 1];
	sessions->peer_len--;

	return 0;
}

int
send_msg(sessions_t *sessions, int peer, char *msg, int msg_size)
{
	SSL_write(sessions->peers[peer]->ssl, msg, msg_size);

	return 0;
}

int
send_msg_all(sessions_t *sessions, char *msg, int msg_size)
{
	for (int c = 0; c < sessions->peer_len; c++) {
		SSL_write(sessions->peers[c]->ssl, msg, msg_size);
	}

	return 0;
}

static void *
server(void *data)
{
	int id           = *((int *)data);
	server_t *server = malloc(sizeof(server_t));

	sessions_t *sessions;
	sessions           = malloc(sizeof(sessions_t));
	sessions->peer_len = 0;
	sessions->peers    = malloc(sizeof(peer_t*) * config->sessions);

	struct sockaddr_in peer_addr;
	socklen_t peer_addr_size = sizeof(struct sockaddr_in);

	logger(LOG_DEBUG, "[%d] building socket", id);
	server->fd = create_socket();

	logger(LOG_DEBUG, "[%d] building TLS context", id);
	server->ctx = create_context();
	logger(LOG_DEBUG, "[%d] configuring TLS context", id);
	configure_context(server->ctx);

	logger(LOG_DEBUG, "[%d] constructing event loop", id);
	struct epoll_event ev, events[SOMAXCONN];
	int nfds, n, p, peer_fd;

	if ((server->epollfd = epoll_create1(0)) == -1) {
		logger(LOG_ERR, "failed to create fd loop (%i) %s", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	ev.events = EPOLLIN|EPOLLET;
	ev.data.fd = server->fd;
	if (epoll_ctl(server->epollfd, EPOLL_CTL_ADD, server->fd, &ev) == -1) {
		logger(LOG_ERR, "failed to add listening socket to fd loop (%i) %s", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	ev.data.fd = intercom->pairs[id]->fd[1];
	if (epoll_ctl(server->epollfd, EPOLL_CTL_ADD, intercom->pairs[id]->fd[1], &ev) == -1) {
		logger(LOG_ERR, "failed to add listening socket to fd loop (%i) %s", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	logger(LOG_DEBUG, "[%d] Added event loop", id);
	for (;;) {
		if ((nfds = epoll_wait(server->epollfd, events, SOMAXCONN, -1)) == -1) {
			logger(LOG_ERR, "catastropic epoll_wait (%i) %s", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}

		for (n = 0; n < nfds; ++n) {
			if (events[n].events & EPOLLIN) {
				if (events[n].data.fd == server->fd) {
					if ((peer_fd = accept(server->fd, (struct sockaddr *) &peer_addr, &peer_addr_size)) == -1) {
						if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
							continue; // break;
						} else {
							logger(LOG_ERR, "unable to accept connections (%i) %s", errno, strerror(errno));
							exit(EXIT_FAILURE);
						}
					}
					add_client(server, sessions, peer_addr, peer_fd);
					logger(LOG_INFO, "[%d] now has %d sessions\n", id, sessions->peer_len);
				} else if (events[n].data.fd == intercom->pairs[id]->fd[1]) {
					char buf[1024];
					read(intercom->pairs[id]->fd[1], buf, 1024);
					if (strncmp("bcast", buf, 5) == 0) {
						send_msg_all(sessions, buf + 5, 1024 - 5);
					}
					memset(buf, 0, 1024);
				} else {
					for (p = 0; p < sessions->peer_len; p++) {
						if (events[n].data.fd == sessions->peers[p]->fd) {
							char buf[1024];
							int len;
							len = SSL_read(sessions->peers[p]->ssl, buf, 1024);
							if (len > 0) {
								char msg[1024];
								logger(LOG_INFO, "%s:%u - %s", inet_ntoa(sessions->peers[p]->addr.sin_addr),
									ntohs(sessions->peers[p]->addr.sin_port), buf);
								sprintf(msg, "%s:%u - %s", inet_ntoa(sessions->peers[p]->addr.sin_addr),
									ntohs(sessions->peers[p]->addr.sin_port), buf);
								char imsg[1024] = "bcast";
								strncat(imsg, msg, 1024 - 6);
								for (int c = 0; c < config->workers; c++) {
									if (c != id)
										send(intercom->pairs[c]->fd[0], imsg, 1024, 0);
								}
								send_msg_all(sessions,msg,1024);
								memset(imsg, 0, 1024);

								if (strncmp(buf, "done", 4) == 0) {
									memset(msg, 0, 1200);
									sprintf(msg, "server hanging up\n");
									send_msg(sessions, p, msg, 1200);
									logger(LOG_INFO, "%s:%u - %s", inet_ntoa(sessions->peers[p]->addr.sin_addr),
										ntohs(sessions->peers[p]->addr.sin_port), "closing connection for\n");
									delete_client(server, sessions, p);
									logger(LOG_INFO, "[%d] now has %d sessions\n", id, sessions->peer_len);
								}
								//free(msg);
							} else if (len <= 0) {
								if (errno != EAGAIN) {
									logger(LOG_INFO, "%s:%u - hangup\n", inet_ntoa(sessions->peers[p]->addr.sin_addr),
										ntohs(sessions->peers[p]->addr.sin_port));
									delete_client(server, sessions, p);
									logger(LOG_INFO, "[%d] now has %d sessions\n", id, sessions->peer_len);
								}
							}
							memset(buf, 0, 1024);
							//break;
						}
					}
				}
			}
		}
	}

	close(server->fd);
	SSL_CTX_free(server->ctx);

	return (NULL);
}

int
main(int argc, char *argv[])
{
	init_openssl();

	config            = malloc(sizeof(config_t));
	config->workers   = sysconf(_SC_NPROCESSORS_ONLN);
	config->sessions  = 1024;
	config->daemonize = 1;
	config->verbose   = 0;
	config->pid       = strdup("/run/tls-server.pid");
	config->uid       = strdup("tlsserver");
	config->gid       = strdup("tlsserver");

	config->certs.chain = strdup("/path-to-tls-certs/cert.pem");
	config->certs.key   = strdup("/path-to-tls-certs/key.pem");


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
			config->pid = strdup(optarg);
			break;
		case 'u':
			config->uid = strdup(optarg);
			break;
		case 'g':
			config->gid = strdup(optarg);
			break;
		default:
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
	logger(LOG_INFO, "starting up");

	struct epoll_event ev, events[SOMAXCONN];
	int nfds, n, epollfd, fl;

	intercom = malloc(sizeof(comm_t));
	intercom->len   = 0;
	intercom->pairs = malloc(sizeof(pair_t*) * config->workers);
	if ((epollfd = epoll_create1(0)) == -1) {
		logger(LOG_ERR, "failed to create fd loop (%i) %s", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	logger(LOG_DEBUG, "spooling %d workers", config->workers);
	pthread_t threads[config->workers];
	for (int i = 0; i < config->workers; i++) {
		intercom->pairs[intercom->len] = malloc(sizeof(pair_t));
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, intercom->pairs[intercom->len]->fd) != 0) {
			logger(LOG_ERR, "failed opening stream socket pair (%i) %s", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}

		fl = fcntl(intercom->pairs[intercom->len]->fd[0], F_GETFL);
		if (fcntl(intercom->pairs[intercom->len]->fd[0], F_SETFL, fl|O_NONBLOCK|O_ASYNC) != 0) {
			logger(LOG_ERR, "failed to set intercom pair non-blocking (%i) %s", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
		fl = fcntl(intercom->pairs[intercom->len]->fd[1], F_GETFL);
		if (fcntl(intercom->pairs[intercom->len]->fd[1], F_SETFL, fl|O_NONBLOCK|O_ASYNC) != 0) {
			logger(LOG_ERR, "failed to set intercom pair non-blocking (%i) %s", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}

		ev.events  = EPOLLIN|EPOLLET;
		ev.data.fd = intercom->pairs[intercom->len]->fd[0];
		if (epoll_ctl(epollfd, EPOLL_CTL_ADD, intercom->pairs[intercom->len]->fd[0], &ev) == -1) {
			logger(LOG_ERR, "failed to add listening socket to fd loop (%i) %s", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
		int d = i;
		pthread_create(threads + i, NULL, &server, (void *)&d);
		intercom->len++;
	}
	logger(LOG_DEBUG, "main thread initialized");
	for (;;) {
		if ((nfds = epoll_wait(epollfd, events, SOMAXCONN, -1)) == -1) {
			for (n = 0; n < nfds; ++n) {
				if (events[n].events & EPOLLIN) {

				}
			}
		}
	}

	for (int i = 0; i < config->workers; i++)
		pthread_join(threads[i], NULL);

	cleanup_openssl();

	return 0;
}
