#ifndef _TLS_SERVER_H
#define _TLS_SERVER_H

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

typedef struct {
	int     daemonize;
	int     workers;
	int     sessions;
	int     verbose;
	int     port;
	char   *address;
	char   *conf;
	char   *pid;
	char   *uid;
	char   *gid;
	struct {
		char *key;
		char *chain;
	} certs;
	struct  sockaddr_in addr;
	struct {
		char *facility;
		char *type;
		char *level;
	} log;
} config_t;

#endif
