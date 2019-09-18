#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <getopt.h>

#include <string.h>
#include "utils.h"
#include "log.h"

typedef struct {
	int   verbose;
	int   port;
	char *address;
	char *ca;
	char *cert;
	char *key;
} conf_t;
conf_t *config;

void init_ssl_opts(SSL_CTX* ctx) {
	if (!SSL_CTX_set_cipher_list(ctx, "AES128-GCM-SHA256")) {
		logger(LOG_ERR, "Could not set cipher list [%s]",
			ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}
	if (!SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION)) {
		logger(LOG_ERR, "Could not disable compression [%s]",
			ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}
	if (SSL_CTX_load_verify_locations(ctx, config->ca, 0) <= 0) {
		logger(LOG_ERR, "Unable to set verify locations [%s]",
			ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}
	if (SSL_CTX_use_certificate_file(ctx, config->cert, SSL_FILETYPE_PEM) <= 0) {
		logger(LOG_ERR, "Could not load cert file(%s) [%s]",
			config->cert, ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, config->key, SSL_FILETYPE_PEM) <= 0) {
		logger(LOG_ERR, "Could not load key file(%s) [%s]",
			config->key, ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		logger(LOG_ERR, "Private key does not match public key in certificate [%s]",
			ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT|SSL_VERIFY_CLIENT_ONCE, 0);
}

int client (void)
{
	const SSL_METHOD *meth = TLS_client_method();
	SSL_CTX* ctx;
	SSL* ssl;
	int err;
	int sd;
	struct sockaddr_in sa;
	char buf[4096];

	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	ctx = SSL_CTX_new(meth);

	init_ssl_opts(ctx);
	sd = socket(AF_INET, SOCK_STREAM, 0);

	int flags = fcntl(sd, F_GETFL, 0);
	if (flags < 0) {
		exit(12);
	}
	fcntl(sd, F_SETFL, flags|O_NONBLOCK);

	memset(&sa, 0, sizeof(sa));
	sa.sin_family      = AF_INET;
	sa.sin_addr.s_addr = inet_addr(config->address);
	sa.sin_port        = htons(config->port);

	printf("Connected to server %s, port %u\n", inet_ntoa(sa.sin_addr),
			ntohs(sa.sin_port));

	err = connect(sd, (struct sockaddr*) &sa, sizeof(sa));
	if (err < 0 && errno != EINPROGRESS) {
		perror("connect != EINPROGRESS");
		exit (15);
	}

	int efd = epoll_create1(0);
	if (efd == -1) {
		perror("epoll_create");
		exit(1);
	}

	struct epoll_event ev;
	ev.data.fd = sd;
	ev.events  = EPOLLIN|EPOLLOUT|EPOLLET|EPOLLERR|EPOLLHUP;

	int s = epoll_ctl(efd, EPOLL_CTL_ADD, sd, &ev);
	if (s == -1) {
		perror("epoll_ctl");
		exit(2);
	}

	int fl = fcntl(STDIN_FILENO, F_GETFL);
	fcntl(STDIN_FILENO, F_SETFL, fl|O_NONBLOCK);
	ev.data.fd = STDIN_FILENO;
	ev.events  = EPOLLIN|EPOLLET;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, STDIN_FILENO, &ev) == -1) {
		logger(LOG_ERR, "failed to add stdin to epoll [%d] [%s]", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	ssl = SSL_new(ctx);

	SSL_set_fd(ssl, sd);
	SSL_set_connect_state(ssl);

	for (;;) {
		int success = SSL_connect(ssl);

		if (success < 0) {
			err = SSL_get_error(ssl, success);

			if (err == SSL_ERROR_WANT_READ||err == SSL_ERROR_WANT_WRITE
					||err == SSL_ERROR_WANT_X509_LOOKUP) {
				continue;
			} else if (err == SSL_ERROR_ZERO_RETURN) {
				printf("SSL_connect: close notify received from peer");
				exit(18);
			} else {
				printf("Error SSL_connect: %d", err);
				fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
				SSL_free(ssl);
				close(sd);
				close(efd);
				exit(16);
			}
		} else
			break;
	}

	struct epoll_event* events = calloc(SOMAXCONN, sizeof ev);

	for (;;) {
		int n = epoll_wait(efd, events, SOMAXCONN, -1);
		if (n < 0 && n == EINTR) {
			printf("epoll_wait System call interrupted. Continue..");
			continue;
		}

		int i, index;
		char data[4096], buf2[64];
		for (i = 0; i < n; i++) {
			if (events[i].data.fd ==  sd) {
				if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)
						|| (!(events[i].events & (EPOLLIN | EPOLLOUT)))) {
					/* An error has occurred on this socket or the socket is not
					 ready for reading (why were we notified then?) */
					fprintf(stderr, "epoll error\n");
					close(events[i].data.fd);
					continue;
				} else if (events[i].events & (EPOLLIN | EPOLLHUP)) {
					err = SSL_read(ssl, buf, sizeof(buf) - 1);
					buf[err] = '\0';
					printf("> %s\n", buf);

					if (err <= 0) {
						if (err == SSL_ERROR_WANT_READ ||
							err == SSL_ERROR_WANT_WRITE ||
							err == SSL_ERROR_WANT_X509_LOOKUP) {
							printf("Read could not complete. Will be invoked later.");
							break;
						} else if(err == SSL_ERROR_ZERO_RETURN) {
							printf("SSL_read: close notify received from peer");
							return 0;
						} else {
							printf("Error during SSL_read");
							exit(17);
						}
					}
					// exit(0);
				} else if (events[i].events & EPOLLOUT) {
					err = SSL_write(ssl, "PING", strlen("PING"));

					if (err <= 0) {
						if (err == SSL_ERROR_WANT_READ ||
							err == SSL_ERROR_WANT_WRITE ||
							err == SSL_ERROR_WANT_X509_LOOKUP) {
							printf("Write could not complete. Will be invoked later.");
							break;
						} else if(err == SSL_ERROR_ZERO_RETURN) {
							printf("SSL_write: close notify received from peer");
							return 0;
						} else {
							printf("Error during SSL_write");
							exit(17);
						}
					}
				}
			} else if (events[i].data.fd == STDIN_FILENO) {
				index = 0;
				int len;
				while ((len = read(STDIN_FILENO, buf2, 64)) > 0) {
					memcpy(data + index, buf2, len);
					memset(buf2, 0, 64);
					index += len;
					if (len < 64)
						break;
				}
				if (index == 0)
					index++;
				data[index - 1] = '\0';
				err = SSL_write(ssl, data, index * 64);
				memset(data, 0, 4096);
				if (err <= 0) {
					if (err == SSL_ERROR_WANT_READ ||
						err == SSL_ERROR_WANT_WRITE ||
						err == SSL_ERROR_WANT_X509_LOOKUP) {
						printf("Read could not complete. Will be invoked later.");
						break;
					} else if(err == SSL_ERROR_ZERO_RETURN) {
						printf("SSL_read: close notify received from peer");
						return 0;
					} else {
						printf("Error during SSL_read");
						exit(EXIT_FAILURE);
					}
				}
			}
		}
	}
	free(events);
	close(sd);
	close(efd);
	return 0;
}

int
main(int argc, char *argv[])
{
	config = malloc(sizeof(conf_t));
	config->port    =  3003;
	config->address = strdup("127.0.0.1");
	config->cert    = strdup("client.cert.pem");
	config->key     = strdup("client.key.pem");
	config->key     = strdup("ca.chain.pem");
	config->verbose = 0;
	struct option long_opts[] = {
		{ "help",             no_argument, NULL, 'h' },
		{ "verbose",          no_argument, NULL, 'v' },
		{ "addreses",   required_argument, NULL, 'a' },
		{ "port",       required_argument, NULL, 'p' },
		{ "ca",         required_argument, NULL, 'C' },
		{ "cert",       required_argument, NULL, 'c' },
		{ "key",        required_argument, NULL, 'k' },
		{ 0, 0, 0, 0 },
	};
	for (;;) {
		int idx = 1;
		int c = getopt_long(argc, argv, "h?v+a:p:C:c:k:", long_opts, &idx);
		if (c == -1) break;

		switch (c) {
		case 'h':
		case '?':
			printf("%s v%s\n", "tls-client", "0.0.1");
			printf("Usage: %s [-h?Fv]\n"
			       "          \n\n",
			        "tls-client");

			printf("Options:\n");
			printf("  -?, -h, --help    show this help screen\n");
			printf("  -v, --verbose     increase debugging\n");

			printf("  -a, --address     the address to connect to\n");
			printf("                    default: 127.0.0.1\n");
			printf("  -p, --port        the port to connect to\n");
			printf("                    default: 3003\n");

			printf("  -C, --ca          the ca chain file to use\n");
			printf("                    default: ./ca.chain.pem\n");
			printf("  -c, --cert        the client cert file to load\n");
			printf("                    default: ./client.cert.pem\n");
			printf("  -k, --key         the the client key file to use\n");
			printf("                    default: ./client.key.pem\n");

			printf("See also: \n  %s\n", "https://github.com/dmolik/tls-server"); // PACKAGE_URL);

			exit(EXIT_SUCCESS);

		case 'v':
			config->verbose++;
			break;
		case 'p':
			config->port    = atoi(optarg);
			break;
		case 'a':
			config->address = strdup(optarg);
			break;
		case 'C':
			config->ca      = strdup(optarg);
			break;
		case 'c':
			config->cert    = strdup(optarg);
			break;
		case 'k':
			config->key     = strdup(optarg);
			break;
		default:
			free(config);
			fprintf(stderr, "unhandled option flag %#02x\n", c);
			return 1;
		}
	}
	log_open("tls-client", "console");
	log_level(LOG_ERR + config->verbose, NULL);

	client();
	return 0;
}
