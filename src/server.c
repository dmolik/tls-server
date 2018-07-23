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

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "log.h"
#include "server.h"

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

	method = TLSv1_2_server_method();

	if (!(ctx = SSL_CTX_new(method))) {
		logger(LOG_ERR, "failed to create TLS context [%s]",
			ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}

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

	logger(LOG_DEBUG, "loading CA chain file");
	if (SSL_CTX_load_verify_locations(ctx, config->certs.ca, NULL) <= 0) {
		logger(LOG_ERR, "failed to load ca chain file(%s) [%s]",
			config->certs.ca, ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}
	logger(LOG_DEBUG, "Setting client CA list");
	SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(config->certs.ca));

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

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

	return ctx;
}

int
add_client(server_t *server, sessions_t *sessions, struct sockaddr_in peer_addr, int peer_fd) {
	if ((sessions->peers[sessions->peer_len] = (peer_t *) malloc(sizeof(peer_t))) == NULL) {
		logger(LOG_ERR, "failed to add session (mem)");
		exit(EXIT_FAILURE);
	}
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
	for (int i = p; i < sessions->peer_len - 1; i++)
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
	int id = *((int *)data);
	logger(LOG_DEBUG, "initializing thread %d", id);
	server_t *server;
	if ((server = malloc(sizeof(server_t))) == NULL) {
		logger(LOG_ERR, "[%d[ failed to allocate thread configuration (mem)", id);
		exit(EXIT_FAILURE);
	}
	memset(server, 0, sizeof(server_t));
	sessions_t *sessions;
	if ((sessions = malloc(sizeof(sessions_t))) == NULL) {
		logger(LOG_ERR, "[%d[ failed to allocate session configuration (mem)", id);
		exit(EXIT_FAILURE);
	}
	memset(sessions, 0, sizeof(sessions_t));
	if ((sessions->peers = (peer_t **) malloc(sizeof(peer_t*) * config->sessions)) == NULL) {
		logger(LOG_ERR, "[%d[ failed to allocate session storage (mem)", id);
		exit(EXIT_FAILURE);
	}
	memset(sessions->peers, 0, sizeof(peer_t*) * config->sessions);

	struct sockaddr_in peer_addr;
	socklen_t peer_addr_size = sizeof(struct sockaddr_in);

	server->fd = create_socket();

	server->ctx = create_context();

	logger(LOG_DEBUG, "[%d] constructing event loop", id);
	struct epoll_event ev, events[SOMAXCONN];
	int nfds, n, p, peer_fd;
	memset(&ev, 0, sizeof(struct epoll_event));

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

	ev.events  = EPOLLIN|EPOLLET;
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
					logger(LOG_DEBUG, "[%d] incomming intercom message", id);
					char buf[1024];
					int len;
					if ((len = read(intercom->pairs[id]->fd[1], buf, 1024)) <= 0) {
						if (errno != EAGAIN)
							logger(LOG_WARNING, "[%d] intercom broadcast is crumulent (%i) [%s]", errno, strerror(errno));
						continue;
					}
					logger(LOG_DEBUG, "[%d] checking intercom message", id);
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
								sprintf(msg, "%.25s:%hu - %.988s", inet_ntoa(sessions->peers[p]->addr.sin_addr),
									ntohs(sessions->peers[p]->addr.sin_port), buf);
								char imsg[1024] = "bcast";
								strncat(imsg, msg, 1024 - 6);
								for (int c = 0; c < config->workers; c++) {
									if (c != id) {
										logger(LOG_DEBUG, "sending to %d worker", c);
										if (send(intercom->pairs[c]->fd[0], imsg, 1024, 0) < 0) {
											logger(LOG_ERR, "failed to send to worker %d (%i) %s", c, errno, strerror(errno));

										}
									}
								}
								// send(intercom->pairs[id]->fd[1], imsg, 1024, 0);
								send_msg_all(sessions,msg,1024);
								memset(imsg, 0, 1024);

								if (strncmp(buf, "done", 4) == 0) {
									memset(msg, 0, 1024);
									sprintf(msg, "server hanging up\n");
									send_msg(sessions, p, msg, 1024);
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

int serve(config_t *conf)
{
	logger(LOG_INFO, "starting up");
	init_openssl();
	config = conf;
	struct epoll_event ev, events[SOMAXCONN];
	int nfds, n, epollfd, fl, id;

	if ((intercom = malloc(sizeof(comm_t))) == NULL) {
		logger(LOG_ERR, "failed to allocate global intercom (mem)");
		exit(EXIT_FAILURE);
	}
	memset(intercom, 0, sizeof(comm_t));
	if ((intercom->pairs = (pair_t **) malloc(sizeof(pair_t*) * config->workers)) == NULL) {
		logger(LOG_ERR, "failed to allocate intercom pairs (mem)");
		exit(EXIT_FAILURE);
	}
	memset(intercom->pairs, 0, sizeof(pair_t*) * config->workers);
	if ((epollfd = epoll_create1(0)) == -1) {
		logger(LOG_ERR, "failed to create fd loop (%i) %s", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	logger(LOG_DEBUG, "spooling intercom with %d comms", config->workers);
	pthread_t threads[config->workers];
	id = 0;
	for (int i = 0; i < config->workers; i++) {
		if ((intercom->pairs[intercom->len] = (pair_t *) malloc(sizeof(pair_t))) == NULL) {
			logger(LOG_ERR, "failed to allocate intercom pair (mem)");
			exit(EXIT_FAILURE);
		}
		memset(intercom->pairs[intercom->len], 0, sizeof(pair_t));
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

		memset(&ev, 0, sizeof(struct epoll_event));
		ev.events  = EPOLLIN|EPOLLET;
		ev.data.fd = intercom->pairs[intercom->len]->fd[0];
		if (epoll_ctl(epollfd, EPOLL_CTL_ADD, intercom->pairs[intercom->len]->fd[0], &ev) == -1) {
			logger(LOG_ERR, "failed to add listening socket to fd loop (%i) %s", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
		pthread_create(threads + i, NULL, &server, (void *)&id);
		id = i;
		intercom->len++;
	}
	logger(LOG_DEBUG, "initialized %d threads", id + 1);
	logger(LOG_DEBUG, "main thread initialized");
	for (;;) {
		if ((nfds = epoll_wait(epollfd, events, SOMAXCONN, -1)) == -1) {
			for (n = 0; n < nfds; ++n) {
				if (events[n].events & EPOLLIN) {
					for (int i = 0; i < intercom->len; i++) {
						if (events[n].data.fd == intercom->pairs[i]->fd[0]) {
							logger(LOG_DEBUG, "[%d] checking intercom message", i);
							int len = 0;
							char buf[1024];
							memset(buf, 0, 1024);
							if ((len = read(intercom->pairs[i]->fd[0], buf, 1024)) <= 0) {
								if (errno != EAGAIN)
									logger(LOG_WARNING, "[%d] intercom broadcast is crumulent (%i) [%s]", errno, strerror(errno));
								continue;
							}
							if (strncmp("bcast", buf, 5) == 0) {
								for (int c = 0; c < intercom->len; c++) {
									logger(LOG_DEBUG, "master sending to %d worker", c);
									if (c != i)
										send(intercom->pairs[c]->fd[0], buf, 1024, 0);
								}
							}
						}
					}
				}
			}
		}
	}

	for (int i = 0; i < config->workers; i++)
		pthread_join(threads[i], NULL);

	cleanup_openssl();

	return 0;
}
