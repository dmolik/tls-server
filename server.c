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


typedef struct {
	int  fd;
	SSL *ssl;
	struct sockaddr_in addr;
} peer_t;

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

int main(void)
{
	int serv_fd;
	SSL_CTX *ctx;
	struct sockaddr_in peer_addr;
	socklen_t peer_addr_size = sizeof(struct sockaddr_in);

	init_openssl();
	ctx = create_context();

	configure_context(ctx);

	serv_fd = create_socket(3001);
	// int fl = fcntl(serv_fd, F_GETFL);
	// fcntl(serv_fd, F_SETFL, fl|O_NONBLOCK|O_ASYNC);

	struct epoll_event ev, events[SOMAXCONN];
	int nfds, epollfd, n, p, p_len, peer_fd;

	if ((epollfd = epoll_create1(0)) == -1) {
		perror("failed to create fd loop");
		exit(EXIT_FAILURE);
	}
	ev.events = EPOLLIN; //|EPOLLET;
	ev.data.fd = serv_fd;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, serv_fd, &ev) == -1) {
		perror("failed to add listening socket to fd loop");
		exit(EXIT_FAILURE);
	}
	p_len = 0;
	peer_t **peers;
	peers = malloc(sizeof(peer_t**));

	for (;;) {
		if ((nfds = epoll_wait(epollfd, events, SOMAXCONN, -1)) == -1) {
			perror("catastropic epoll_wait");
			exit(EXIT_FAILURE);
		}

		for (n = 0; n < nfds; ++n) {
			if (events[n].events & EPOLLIN) {
				if (events[n].data.fd == serv_fd) {
					if ((peer_fd = accept(serv_fd, (struct sockaddr *) &peer_addr, &peer_addr_size)) == -1) {
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
					peers[p_len] = malloc(sizeof(peer_t));
					peers[p_len]->fd = peer_fd;
					int fl = fcntl(peers[p_len]->fd, F_GETFL);
					fcntl(peers[p_len]->fd, F_SETFL, fl|O_NONBLOCK|O_ASYNC);

					int flags =1;
					if (setsockopt(peers[p_len]->fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&flags, sizeof(flags))) {
						perror("setsocketopt(), SO_KEEPALIVE");
						exit(EXIT_FAILURE);
					}
					flags = 10;
					if (setsockopt(peers[p_len]->fd, SOL_TCP, TCP_KEEPIDLE, (void *)&flags, sizeof(flags))) {
						perror("setsocketopt(), SO_KEEPALIVE");
						exit(EXIT_FAILURE);
					}
					flags = 5;
					if (setsockopt(peers[p_len]->fd, SOL_TCP, TCP_KEEPCNT, (void *)&flags, sizeof(flags))) {
						perror("setsocketopt(), SO_KEEPALIVE");
						exit(EXIT_FAILURE);
					}
					flags = 5;
					if (setsockopt(peers[p_len]->fd, SOL_TCP, TCP_KEEPINTVL, (void *)&flags, sizeof(flags))) {
						perror("setsocketopt(), SO_KEEPALIVE");
						exit(EXIT_FAILURE);
					}

					peers[p_len]->addr = peer_addr;
					peers[p_len]->ssl  = SSL_new(ctx);

					SSL_set_fd(peers[p_len]->ssl, peers[p_len]->fd);
					SSL_set_accept_state(peers[p_len]->ssl);
					SSL_do_handshake(peers[p_len]->ssl);

					ev.events = EPOLLIN|EPOLLET;
					ev.data.fd = peers[p_len]->fd;
					if (epoll_ctl(epollfd, EPOLL_CTL_ADD, peers[p_len]->fd, &ev) == -1) {
						perror("failed to add peer socket to fd loop");
						exit(EXIT_FAILURE);
					}
					printf("Client connected from %s:%u\n", inet_ntoa(peers[p_len]->addr.sin_addr),
						ntohs(peers[p_len]->addr.sin_port));
					p_len++;
					printf("total peers: %d\n", p_len);
				} else {
					for (p = 0; p < p_len; p++) {
						if (events[n].data.fd == peers[p]->fd) {
							char buf[1024];
							int len;
							len = SSL_read(peers[p]->ssl, buf, 1024);
							if (len > 0) {
								printf("%s:%u - %s", inet_ntoa(peers[p]->addr.sin_addr),
									ntohs(peers[p]->addr.sin_port), buf);
								char *msg = malloc(1200);
								memset(msg, 0, 1200);
								sprintf(msg, "%s:%u - %s", inet_ntoa(peers[p]->addr.sin_addr),
									ntohs(peers[p]->addr.sin_port), buf);
								if (strncmp(buf, "done", 4) == 0) {
									memset(msg, 0, 1200);
									sprintf(msg, "server hanging up\n");
									SSL_write(peers[p]->ssl, msg, 1200);
									SSL_shutdown(peers[p]->ssl);
									SSL_free(peers[p]->ssl);
									epoll_ctl(epollfd, EPOLL_CTL_DEL, peers[p]->fd, &ev);
								}
								for (int c = 0; c < p_len; c++) {
									if (c != p)
										SSL_write(peers[c]->ssl, msg, 1200);
								}
								free(msg);
							}
							if (len <= 0) {
								if (errno != EAGAIN) {
									printf("%s:%u - hangup\n", inet_ntoa(peers[p]->addr.sin_addr),
										ntohs(peers[p]->addr.sin_port));
									SSL_shutdown(peers[p]->ssl);
									SSL_free(peers[p]->ssl);
									epoll_ctl(epollfd, EPOLL_CTL_DEL, peers[p]->fd, &ev);
								}
							}
							memset(buf, 0, 1024);
						}
					}
				}
			}
		}
	}

	close(serv_fd);
	SSL_CTX_free(ctx);
	cleanup_openssl();
}
