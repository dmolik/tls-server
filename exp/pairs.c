#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/epoll.h>

typedef struct {
	int fd[2];
} sockpair;

typedef struct {
	int        len;
	sockpair **socks;
} comms_t;
comms_t *comms;

static void *
child(void *data)
{
	int id = (int)data;
	printf("in thread %d\n", id);
	struct epoll_event ev, events[SOMAXCONN];
	int nfds, n, epollfd;

	if ((epollfd = epoll_create1(0)) == -1) {
		perror("failed to create fd loop");
		exit(EXIT_FAILURE);
	}
	ev.events = EPOLLIN|EPOLLET;
	ev.data.fd = comms->socks[id]->fd[1];
	printf("adding sock pair [%d, %d] to thread %d\n", comms->socks[id]->fd[0], comms->socks[id]->fd[1], id);
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, comms->socks[id]->fd[1], &ev) == -1) {
		perror("failed to add listening socket to fd loop");
		exit(EXIT_FAILURE);
	}
	char buf[1024];
	const char *str = "hello from thread 3\n";
	for (;;) {
		if (id == 3) {
			sleep(1);
			for (int i = 0; i< comms->len;i++) {
				if (i != id) {
					printf("writing to %d\n", i);
					write(comms->socks[i]->fd[0], str, strlen(str) + 1);
				}
			}
		} else {
			printf("thread %d entering wait\n", id);
			if ((nfds = epoll_wait(epollfd, events, SOMAXCONN, -1)) == -1) {
				perror("catastropic epoll_wait");
				exit(EXIT_FAILURE);
			}
			for (n = 0; n < nfds; n++) {
				if (events[n].data.fd == comms->socks[id]->fd[1]) {
					read(comms->socks[id]->fd[1], buf, 1024);
					printf("%d --> %s\n", id, buf);
				}
			}

		}
	}

	return (NULL);
}

int main(void)
{
	pthread_t threads[5];
	comms = malloc(sizeof(comms_t));
	comms->len   = 0;
	comms->socks = malloc(sizeof(sockpair*) * 5);
	for (int i = 0; i < 5; i++) {
		comms->socks[comms->len] = malloc(sizeof(sockpair));
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, comms->socks[comms->len]->fd) < 0) {
			perror("opening stream socket pair");
			exit(1);
		}
		pthread_create(threads + i, NULL, &child, (void *)i);
		comms->len++;
	}
	for (int i = 0; i < 5; i++)
		pthread_join(threads[i], NULL);

	return 0;
}
