#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <assert.h>
#include <errno.h>
#include <sys/sysmacros.h>
#include <pthread.h>

#include <urcu/arch.h>
#include <urcu/tls-compat.h>
#include <urcu/uatomic.h>
#include "thread-id.h"

/* hardcoded number of CPUs */
#define NR_CPUS 16384

#ifndef DYNAMIC_LINK_TEST
#define _LGPL_SOURCE
#endif
#include <urcu/wfcqueue.h>

typedef struct {
	int  fd;
	SSL *ssl;
	struct sockaddr_in addr;
} peer_t;

typedef struct {
	int       fd;
	int       epollfd;
	int       peer_len;
	SSL_CTX  *ctx;
	peer_t  **peers;
} server_t;

int create_socket(int port)
{
	int s;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror("Unable to create socket");
		exit(EXIT_FAILURE);
	}
	int opt = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const void*)&opt,
		sizeof(int));
	setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (const void*)&opt,
		sizeof(int));

	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Unable to bind");
		exit(EXIT_FAILURE);
	}

	if (listen(s, SOMAXCONN) < 0) {
		perror("Unable to listen");
		exit(EXIT_FAILURE);
	}

	return s;
}

void init_openssl()
{
	SSL_load_error_strings();	
	OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
	EVP_cleanup();
}

SSL_CTX *create_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = SSLv23_server_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	return ctx;
}

void configure_context(SSL_CTX *ctx)
{
	SSL_CTX_set_ecdh_auto(ctx, 1);

	const long flags = SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1|SSL_OP_NO_COMPRESSION;
	SSL_CTX_set_options(ctx, flags);
	const char *PREFERRED_CIPHERS =
		"kEECDH+ECDSA+AES256:EECDH+RSA+AES256+GCM+SHA384"
		":EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH"
		":HIGH:!aNULL:!eNULL:!EXPORT:!MD5:!RC4:!DES:!SSLv2"
		":!LOW:!CAMELLIA";
	SSL_CTX_set_cipher_list(ctx, PREFERRED_CIPHERS);

	if (SSL_CTX_use_certificate_chain_file(ctx, "cert.pem") <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
}

int add_client(server_t *server, struct sockaddr_in peer_addr, int peer_fd) {
	server->peers[server->peer_len]     = malloc(sizeof(peer_t));
	server->peers[server->peer_len]->fd = peer_fd;
	int fl = fcntl(server->peers[server->peer_len]->fd, F_GETFL);
	fcntl(server->peers[server->peer_len]->fd, F_SETFL, fl|O_NONBLOCK|O_ASYNC);

	int op =1;
	if (setsockopt(server->peers[server->peer_len]->fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&op, sizeof(op))) {
		perror("setsocketopt(), SO_KEEPALIVE");
		exit(EXIT_FAILURE);
	}
	op = 10;
	if (setsockopt(server->peers[server->peer_len]->fd, SOL_TCP, TCP_KEEPIDLE, (void *)&op, sizeof(op))) {
		perror("setsocketopt(), SO_KEEPALIVE");
		exit(EXIT_FAILURE);
	}
	op = 5;
	if (setsockopt(server->peers[server->peer_len]->fd, SOL_TCP, TCP_KEEPCNT, (void *)&op, sizeof(op))) {
		perror("setsocketopt(), SO_KEEPALIVE");
		exit(EXIT_FAILURE);
	}
	op = 5;
	if (setsockopt(server->peers[server->peer_len]->fd, SOL_TCP, TCP_KEEPINTVL, (void *)&op, sizeof(op))) {
		perror("setsocketopt(), SO_KEEPALIVE");
		exit(EXIT_FAILURE);
	}

	server->peers[server->peer_len]->addr = peer_addr;
	server->peers[server->peer_len]->ssl  = SSL_new(server->ctx);

	SSL_set_fd(server->peers[server->peer_len]->ssl,
		server->peers[server->peer_len]->fd);
	SSL_set_accept_state(server->peers[server->peer_len]->ssl);
	SSL_do_handshake(server->peers[server->peer_len]->ssl);

	struct epoll_event ev;
	ev.events = EPOLLIN|EPOLLET;
	ev.data.fd = server->peers[server->peer_len]->fd;
	if (epoll_ctl(server->epollfd, EPOLL_CTL_ADD, server->peers[server->peer_len]->fd, &ev) == -1) {
		perror("failed to add peer socket to fd loop");
		exit(EXIT_FAILURE);
	}
	printf("Client connected from %s:%u\n", inet_ntoa(server->peers[server->peer_len]->addr.sin_addr),
		ntohs(server->peers[server->peer_len]->addr.sin_port));
	server->peer_len++;

	return 0;
}

int delete_client(server_t *server, int p)
{
	SSL_shutdown(server->peers[p]->ssl);
	SSL_free(server->peers[p]->ssl);
	struct epoll_event ev;
	epoll_ctl(server->epollfd, EPOLL_CTL_DEL, server->peers[p]->fd, &ev);
	free(server->peers[p]);
	if (p != server->peer_len)
		server->peers[p] = server->peers[p + 1];
	server->peer_len--;

	return 0;
}

int send_msg(server_t *server, int peer, char *msg, int msg_size)
{
	SSL_write(server->peers[peer]->ssl, msg, msg_size);

	return 0;
}

int send_msg_all(server_t *server, int peer, char *msg, int msg_size)
{
	for (int c = 0; c < server->peer_len; c++) {
		if (c != peer)
			SSL_write(server->peers[c]->ssl, msg, msg_size);
	}

	return 0;
}

int main(void)
{
	server_t *server = malloc(sizeof(server_t));

	struct sockaddr_in peer_addr;
	socklen_t peer_addr_size = sizeof(struct sockaddr_in);

	init_openssl();
	server->ctx = create_context();

	configure_context(server->ctx);

	server->fd = create_socket(3001);
	// int fl = fcntl(serv_fd, F_GETFL);
	// fcntl(serv_fd, F_SETFL, fl|O_NONBLOCK|O_ASYNC);

	struct epoll_event ev, events[SOMAXCONN];
	int nfds, n, p, peer_fd;

	if ((server->epollfd = epoll_create1(0)) == -1) {
		perror("failed to create fd loop");
		exit(EXIT_FAILURE);
	}
	ev.events = EPOLLIN; //|EPOLLET;
	ev.data.fd = server->fd;
	if (epoll_ctl(server->epollfd, EPOLL_CTL_ADD, server->fd, &ev) == -1) {
		perror("failed to add listening socket to fd loop");
		exit(EXIT_FAILURE);
	}
	server->peer_len = 0;
	server->peers    = malloc(sizeof(peer_t**));

	for (;;) {
		if ((nfds = epoll_wait(server->epollfd, events, SOMAXCONN, -1)) == -1) {
			perror("catastropic epoll_wait");
			exit(EXIT_FAILURE);
		}

		for (n = 0; n < nfds; ++n) {
			if (events[n].events & EPOLLIN) {
				if (events[n].data.fd == server->fd) {
					if ((peer_fd = accept(server->fd, (struct sockaddr *) &peer_addr, &peer_addr_size)) == -1) {
						if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
							break;
						} else {
							perror("unable to accept connections");
							exit(EXIT_FAILURE);
						}
					}
					if (peer_fd < 0) {
						perror("Unable to accept");
						exit(EXIT_FAILURE);
					}
					add_client(server, peer_addr, peer_fd);
					printf("total peers: %d\n", server->peer_len);
				} else {
					for (p = 0; p < server->peer_len; p++) {
						if (events[n].data.fd == server->peers[p]->fd) {
							char buf[1024];
							int len;
							len = SSL_read(server->peers[p]->ssl, buf, 1024);
							if (len > 0) {
								printf("%s:%u - %s", inet_ntoa(server->peers[p]->addr.sin_addr),
									ntohs(server->peers[p]->addr.sin_port), buf);
								char *msg = malloc(1200);
								memset(msg, 0, 1200);
								sprintf(msg, "%s:%u - %s", inet_ntoa(server->peers[p]->addr.sin_addr),
									ntohs(server->peers[p]->addr.sin_port), buf);
								send_msg_all(server, p, msg, 1200);
								if (strncmp(buf, "done", 4) == 0) {
									memset(msg, 0, 1200);
									sprintf(msg, "server hanging up\n");
									send_msg(server, p, msg, 1200);
									delete_client(server, p);
								}
								free(msg);
							}
							if (len <= 0) {
								if (errno != EAGAIN) {
									printf("%s:%u - hangup\n", inet_ntoa(server->peers[p]->addr.sin_addr),
										ntohs(server->peers[p]->addr.sin_port));
									delete_client(server, p);
								}
							}
							memset(buf, 0, 1024);
							break;
						}
					}
				}
			}
		}
	}

	close(server->fd);
	SSL_CTX_free(server->ctx);
	cleanup_openssl();
}
