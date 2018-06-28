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

typedef struct {
	int  fd;
	SSL *ssl;
	struct sockaddr_in addr;
} peer_t;

typedef struct {
	int               peer_len;
	pthread_mutex_t  *lock;
	peer_t          **peers;
} sessions_t;

typedef struct {
	int       fd;
	int       epollfd;
	SSL_CTX  *ctx;
} server_t;

sessions_t *sessions;

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

	int fl = fcntl(s, F_GETFL);
	fcntl(s, F_SETFL, fl|O_NONBLOCK|O_ASYNC);

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

//void configure_context(SSL_CTX *ctx, sessions_t *sessions)
void configure_context(SSL_CTX *ctx)
{
	//pthread_mutex_lock(sessions->lock);
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
	// pthread_mutex_unlock(sessions->lock);
}

int add_client(server_t *server, sessions_t *sessions, struct sockaddr_in peer_addr, int peer_fd) {
	pthread_mutex_lock(sessions->lock);
	sessions->peers[sessions->peer_len]     = malloc(sizeof(peer_t));
	sessions->peers[sessions->peer_len]->fd = peer_fd;
	int fl = fcntl(sessions->peers[sessions->peer_len]->fd, F_GETFL);
	fcntl(sessions->peers[sessions->peer_len]->fd, F_SETFL, fl|O_NONBLOCK|O_ASYNC);

	int op =1;
	if (setsockopt(sessions->peers[sessions->peer_len]->fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&op, sizeof(op))) {
		perror("setsocketopt(), SO_KEEPALIVE");
		exit(EXIT_FAILURE);
	}
	op = 10;
	if (setsockopt(sessions->peers[sessions->peer_len]->fd, SOL_TCP, TCP_KEEPIDLE, (void *)&op, sizeof(op))) {
		perror("setsocketopt(), SO_KEEPALIVE");
		exit(EXIT_FAILURE);
	}
	op = 5;
	if (setsockopt(sessions->peers[sessions->peer_len]->fd, SOL_TCP, TCP_KEEPCNT, (void *)&op, sizeof(op))) {
		perror("setsocketopt(), SO_KEEPALIVE");
		exit(EXIT_FAILURE);
	}
	op = 5;
	if (setsockopt(sessions->peers[sessions->peer_len]->fd, SOL_TCP, TCP_KEEPINTVL, (void *)&op, sizeof(op))) {
		perror("setsocketopt(), SO_KEEPALIVE");
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
		perror("failed to add peer socket to fd loop");
		exit(EXIT_FAILURE);
	}
	printf("Client connected from %s:%u\n", inet_ntoa(sessions->peers[sessions->peer_len]->addr.sin_addr),
		ntohs(sessions->peers[sessions->peer_len]->addr.sin_port));
	sessions->peer_len++;
	pthread_mutex_unlock(sessions->lock);

	return 0;
}

int delete_client(server_t *server, sessions_t *sessions, int p)
{
	pthread_mutex_lock(sessions->lock);
	SSL_shutdown(sessions->peers[p]->ssl);
	SSL_free(sessions->peers[p]->ssl);
	struct epoll_event ev;
	epoll_ctl(server->epollfd, EPOLL_CTL_DEL, sessions->peers[p]->fd, &ev);
	free(sessions->peers[p]);
	if (p < sessions->peer_len)
	for (int i = p; i < sessions->peer_len; i++)
		sessions->peers[i] = sessions->peers[i + 1];
	sessions->peer_len--;
	pthread_mutex_unlock(sessions->lock);

	return 0;
}

int send_msg(sessions_t *sessions, int peer, char *msg, int msg_size)
{
	SSL_write(sessions->peers[peer]->ssl, msg, msg_size);

	return 0;
}

int send_msg_all(sessions_t *sessions, int peer, char *msg, int msg_size)
{
	for (int c = 0; c < sessions->peer_len; c++) {
		if (c != peer)
			SSL_write(sessions->peers[c]->ssl, msg, msg_size);
	}

	return 0;
}

static void *
server(void *data)
{
	sessions_t *sessions = (sessions_t *) data;
	server_t *server = malloc(sizeof(server_t));

	struct sockaddr_in peer_addr;
	socklen_t peer_addr_size = sizeof(struct sockaddr_in);

	server->fd = create_socket(3002);

	server->ctx = create_context();
	configure_context(server->ctx);

	struct epoll_event ev, events[SOMAXCONN];
	int nfds, n, p, peer_fd;

	if ((server->epollfd = epoll_create1(0)) == -1) {
		perror("failed to create fd loop");
		exit(EXIT_FAILURE);
	}
	ev.events = EPOLLIN|EPOLLET;
	ev.data.fd = server->fd;
	if (epoll_ctl(server->epollfd, EPOLL_CTL_ADD, server->fd, &ev) == -1) {
		perror("failed to add listening socket to fd loop");
		exit(EXIT_FAILURE);
	}
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
					add_client(server, sessions, peer_addr, peer_fd);
					printf("total peers: %d\n", sessions->peer_len);
				} else {
					for (p = 0; p < sessions->peer_len; p++) {
						if (events[n].data.fd == sessions->peers[p]->fd) {
							char buf[1024];
							int len;
							len = SSL_read(sessions->peers[p]->ssl, buf, 1024);
							if (len > 0) {
								printf("%s:%u - %s", inet_ntoa(sessions->peers[p]->addr.sin_addr),
									ntohs(sessions->peers[p]->addr.sin_port), buf);
								char *msg = malloc(1200);
								memset(msg, 0, 1200);
								sprintf(msg, "%s:%u - %s", inet_ntoa(sessions->peers[p]->addr.sin_addr),
									ntohs(sessions->peers[p]->addr.sin_port), buf);
								send_msg_all(sessions, p, msg, 1200);
								if (strncmp(buf, "done", 4) == 0) {
									memset(msg, 0, 1200);
									sprintf(msg, "server hanging up\n");
									send_msg(sessions, p, msg, 1200);
									printf("%s:%u - %s", inet_ntoa(sessions->peers[p]->addr.sin_addr),
										ntohs(sessions->peers[p]->addr.sin_port), "closing connection for\n");
									delete_client(server, sessions, p);
									printf("total peers: %d\n", sessions->peer_len);
								}
								free(msg);
							}
							if (len <= 0) {
								if (errno != EAGAIN) {
									printf("%s:%u - hangup\n", inet_ntoa(sessions->peers[p]->addr.sin_addr),
										ntohs(sessions->peers[p]->addr.sin_port));
									delete_client(server, sessions, p);
									printf("total peers: %d\n", sessions->peer_len);
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

	return (NULL);
}

int main(void)
{
	init_openssl();

	sessions = malloc(sizeof(sessions_t));
	sessions->peer_len   = 0;
	sessions->peers      = malloc(sizeof(peer_t**));
	sessions->lock       = malloc(sizeof(pthread_mutex_t));

	if (pthread_mutex_init(sessions->lock, NULL) != 0) {
		printf("\n mutex init failed\n");
		return 1;
	}

	int num_threads  = 8;
	pthread_t threads[num_threads];

	for (int i = 0; i < num_threads; i++)
		pthread_create(threads + i, NULL, &server, sessions);

	for (int i = 0; i < num_threads; i++)
		pthread_join(threads[i], NULL);

	pthread_mutex_destroy(sessions->lock);
	cleanup_openssl();

	return 0;
}
