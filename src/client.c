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

#include "utils.h"

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
		printf("Could not set cipher list");
		exit(1);
	}
	if (!SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION)) {
		printf("Could not disable compression");
		exit(2);
	}
	if (SSL_CTX_load_verify_locations(ctx, config->cert, 0) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(5);
	}
	if (SSL_CTX_use_certificate_file(ctx, config->cert, SSL_FILETYPE_PEM) <= 0) {
		printf("Could not load cert file: ");
		ERR_print_errors_fp(stderr);
		exit(5);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, config->key, SSL_FILETYPE_PEM) <= 0) {
		printf("Could not load key file");
		ERR_print_errors_fp(stderr);
		exit(6);
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr,
				"Private key does not match public key in certificate.\n");
		exit(7);
	}
	/* Enable client certificate verification. Enable before accepting connections. */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT |
		SSL_VERIFY_CLIENT_ONCE, 0);
}

static void
dump_cert_info(SSL *ssl)
{
	printf("Using cipher %s", SSL_get_cipher(ssl));

	X509 *client_cert = SSL_get_peer_certificate(ssl);
	if (client_cert != NULL) {
		char *str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
		if(str == NULL) {
			printf("warn X509 subject name is null");
		}
		printf("\t Subject: %s\n", str);
		OPENSSL_free(str);

		str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
		if(str == NULL) {
			printf("warn X509 issuer name is null");
		}
		printf("\t Issuer: %s\n", str);
		OPENSSL_free(str);

		/* Deallocate certificate, free memory */
		X509_free(client_cert);
	} else {
		printf("Client does not have certificate.\n");
	}
}

int client (void)
{
	const SSL_METHOD *meth = TLSv1_2_client_method();
	SSL_CTX* ctx;
	SSL* ssl;
	//X509* server_cert;
	int err;
	int sd;
	struct sockaddr_in sa;
	//char* str;
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

	struct epoll_event event;
	event.data.fd = sd;
	event.events = EPOLLIN | EPOLLOUT | EPOLLET |EPOLLERR | EPOLLHUP;

	int s = epoll_ctl(efd, EPOLL_CTL_ADD, sd, &event);
	if (s == -1) {
		perror("epoll_ctl");
		exit(2);
	}

	ssl = SSL_new(ctx);

	SSL_set_fd(ssl, sd);
	SSL_set_connect_state(ssl);

	for (;;) {
		int success = SSL_connect(ssl);

		if (success < 0) {
			err = SSL_get_error(ssl, success);

			if (err == SSL_ERROR_WANT_READ ||
					err == SSL_ERROR_WANT_WRITE ||
					err == SSL_ERROR_WANT_X509_LOOKUP) {
				continue;
			} else if(err == SSL_ERROR_ZERO_RETURN) {
				printf("SSL_connect: close notify received from peer");
				exit(18);
			} else {
				printf("Error SSL_connect: %d", err);
				perror("perror: ");
				SSL_free(ssl);
				close(sd);
				close(efd);
				exit(16);
			}
		} else {
			dump_cert_info(ssl);
			break;
		}
	}

	struct epoll_event* events = calloc(SOMAXCONN, sizeof event);

	for (;;) {
		int n = epoll_wait(efd, events, SOMAXCONN, -1);
		if (n < 0 && n == EINTR) {
			printf("epoll_wait System call interrupted. Continue..");
			continue;
		}

		int i;
		for (i = 0; i < n; i++) {
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)
					|| (!(events[i].events & (EPOLLIN | EPOLLOUT)))) {
				/* An error has occurred on this socket or the socket is not
				 ready for reading (why were we notified then?) */
				fprintf(stderr, "epoll error\n");
				close(events[i].data.fd);
				continue;
			} else if (events->events & (EPOLLIN | EPOLLHUP)) {
				err = SSL_read(ssl, buf, sizeof(buf) - 1);
				buf[err] = '\0';
				printf("Client Received %d chars - '%s'\n", err, buf);

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
				exit(0);
			} else if (events->events & EPOLLOUT) {
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
	client();
	return 0;
}
