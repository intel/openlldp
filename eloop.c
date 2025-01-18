/*
 * Event loop based on select() loop
 * Copyright (c) 2002-2005, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include "eloop.h"
#include "include/messages.h"

#define UNUSED __attribute__((__unused__))

typedef long os_time_t;

/**
 * os_sleep - Sleep (sec, usec)
 * @sec: Number of seconds to sleep
 * @usec: Number of microseconds to sleep
 */
struct os_time {
	os_time_t sec;
	os_time_t usec;
};

/**
 * os_get_time - Get current time (sec, usec)
 * @t: Pointer to buffer for the time
 * Returns: 0 on success, -1 on failure
 */
int os_get_time(struct os_time *t)
{
	int res;
	struct timeval tv;
	res = gettimeofday(&tv, NULL);
	t->sec = tv.tv_sec;
	t->usec = tv.tv_usec;
	return res;
}

/* Helper macros for handling struct os_time */

#define os_time_before(a, b) \
	((a)->sec < (b)->sec || \
	 ((a)->sec == (b)->sec && (a)->usec < (b)->usec))

#define os_time_sub(a, b, res) do { \
	(res)->sec = (a)->sec - (b)->sec; \
	(res)->usec = (a)->usec - (b)->usec; \
	if ((res)->usec < 0) { \
		(res)->sec--; \
		(res)->usec += 1000000; \
	} \
} while (0)


struct eloop_sock {
	struct pollfd pfd;
	void *eloop_data;
	void *user_data;
	eloop_sock_handler handler;
};

struct eloop_timeout {
	struct os_time time;
	void *eloop_data;
	void *user_data;
	eloop_timeout_handler handler;
	struct eloop_timeout *next;
};

struct eloop_signal {
	int sig;
	void *user_data;
	eloop_signal_handler handler;
	int signaled;
};

struct eloop_sock_table {
	int count;
	struct eloop_sock *table;
	int changed;
};

struct eloop_data {
	void *user_data;

	struct eloop_sock_table sock_table;

	struct eloop_timeout *timeout;

	int signal_count;
	struct eloop_signal *signals;
	int signaled;
	int pending_terminate;

	int terminate;
	int reader_table_changed;
};

static struct eloop_data eloop;


int eloop_init(void *user_data)
{
	memset(&eloop, 0, sizeof(eloop));
	eloop.user_data = user_data;
	return 0;
}


static int eloop_sock_table_add_sock(struct eloop_sock_table *table,
                                     struct pollfd pfd, eloop_sock_handler handler,
                                     void *eloop_data, void *user_data)
{
	struct eloop_sock *tmp;

	if (table == NULL)
		return -EINVAL;

	tmp = (struct eloop_sock *)
		realloc(table->table,
			   (table->count + 1) * sizeof(struct eloop_sock));
	if (tmp == NULL)
		return -ENOMEM;

	tmp[table->count].pfd = pfd;
	tmp[table->count].eloop_data = eloop_data;
	tmp[table->count].user_data = user_data;
	tmp[table->count].handler = handler;
	table->count++;
	table->table = tmp;
	table->changed = 1;

	return 0;
}


static void eloop_sock_table_remove_sock(struct eloop_sock_table *table,
                                         int sock)
{
	int i;

	if (table == NULL || table->table == NULL || table->count == 0)
		return;

	for (i = 0; i < table->count; i++) {
		if (table->table[i].pfd.fd == sock)
			break;
	}
	if (i == table->count)
		return;
	if (i != table->count - 1) {
		memmove(&table->table[i], &table->table[i + 1],
			   (table->count - i - 1) *
			   sizeof(struct eloop_sock));
	}
	table->count--;
	table->changed = 1;
}


static void eloop_sock_table_set_fds(struct eloop_sock_table *table,
				     struct pollfd *fds)
{
	int i;

	if (table->table == NULL)
		return;

	for (i = 0; i < table->count; i++)
		fds[i] = table->table[i].pfd;
}


static void eloop_sock_table_dispatch(struct eloop_sock_table *table,
				      struct pollfd *fds, int events)
{
	int i;

	if (table == NULL || table->table == NULL)
		return;

	table->changed = 0;
	for (i = 0; i < table->count; i++) {
		if (fds[i].revents & events) {
			table->table[i].handler(table->table[i].pfd.fd,
						table->table[i].eloop_data,
						table->table[i].user_data);
			if (table->changed)
				break;
		}
	}
}


static void eloop_sock_table_destroy(struct eloop_sock_table *table)
{
	int rc, tc, sock;

	if (table->table) {
		tc = table->count;
		while (tc > 0) {
			sock = table->table[tc].pfd.fd;
			rc = fcntl(sock, F_GETFD);
			if (rc != -1) {
				rc = close(sock);
				if (rc)
					LLDPAD_ERR("Failed to close fd - %s\n",
							strerror(errno));
			}
			tc--;
		}
		free(table->table);
	}
}

static int eloop_register_sock(struct pollfd pfd,
			eloop_sock_handler handler,
			void *eloop_data, void *user_data)
{
	return eloop_sock_table_add_sock(&eloop.sock_table, pfd, handler,
					 eloop_data, user_data);
}


int eloop_register_read_sock(int sock, eloop_sock_handler handler,
			     void *eloop_data, void *user_data)
{
	struct pollfd pfd = {0};
	pfd.fd = sock;
	pfd.events = POLLIN;
	return eloop_register_sock(pfd, handler, eloop_data, user_data);
}


static void eloop_unregister_sock(int sock)
{
	eloop_sock_table_remove_sock(&eloop.sock_table, sock);
}


void eloop_unregister_read_sock(int sock)
{
	eloop_unregister_sock(sock);
}


int eloop_register_timeout(unsigned int secs, unsigned int usecs,
			   eloop_timeout_handler handler,
			   void *eloop_data, void *user_data)
{
	struct eloop_timeout *timeout, *tmp, *prev;

	timeout = malloc(sizeof(*timeout));
	if (timeout == NULL)
		return -1;
	os_get_time(&timeout->time);
	timeout->time.sec += secs;
	timeout->time.usec += usecs;
	while (timeout->time.usec >= 1000000) {
		timeout->time.sec++;
		timeout->time.usec -= 1000000;
	}
	timeout->eloop_data = eloop_data;
	timeout->user_data = user_data;
	timeout->handler = handler;
	timeout->next = NULL;

	if (eloop.timeout == NULL) {
		eloop.timeout = timeout;
		return 0;
	}

	prev = NULL;
	tmp = eloop.timeout;
	while (tmp != NULL) {
		if (os_time_before(&timeout->time, &tmp->time))
			break;
		prev = tmp;
		tmp = tmp->next;
	}

	if (prev == NULL) {
		timeout->next = eloop.timeout;
		eloop.timeout = timeout;
	} else {
		timeout->next = prev->next;
		prev->next = timeout;
	}

	return 0;
}


int eloop_cancel_timeout(eloop_timeout_handler handler,
			 void *eloop_data, void *user_data)
{
	struct eloop_timeout *timeout, *prev, *next;
	int removed = 0;

	prev = NULL;
	timeout = eloop.timeout;
	while (timeout != NULL) {
		next = timeout->next;

		if (timeout->handler == handler &&
		    (timeout->eloop_data == eloop_data ||
		     eloop_data == ELOOP_ALL_CTX) &&
		    (timeout->user_data == user_data ||
		     user_data == ELOOP_ALL_CTX)) {
			if (prev == NULL)
				eloop.timeout = next;
			else
				prev->next = next;
			free(timeout);
			removed++;
		} else
			prev = timeout;

		timeout = next;
	}

	return removed;
}


static void eloop_handle_alarm(int sig)
{
	fprintf(stderr, "eloop: could not process SIGINT or SIGTERM in two "
		"seconds. Looks like there\n"
		"is a bug that ends up in a busy loop that "
		"prevents clean shutdown.\n"
		"Killing program forcefully.\n"
		"sig is %d.\n", sig);
	exit(1);
}


static void eloop_handle_signal(int sig)
{
	int i;

	if ((sig == SIGINT || sig == SIGTERM) && !eloop.pending_terminate) {
		/* Use SIGALRM to break out from potential busy loops that
		 * would not allow the program to be killed. */
		eloop.pending_terminate = 1;
		signal(SIGALRM, eloop_handle_alarm);
		alarm(2);
	}

	eloop.signaled++;
	for (i = 0; i < eloop.signal_count; i++) {
		if (eloop.signals[i].sig == sig) {
			eloop.signals[i].signaled++;
			break;
		}
	}
}


static void eloop_process_pending_signals(void)
{
	int i;

	if (eloop.signaled == 0)
		return;
	eloop.signaled = 0;

	if (eloop.pending_terminate) {
		alarm(0);
		eloop.pending_terminate = 0;
	}

	for (i = 0; i < eloop.signal_count; i++) {
		if (eloop.signals[i].signaled) {
			eloop.signals[i].signaled = 0;
			eloop.signals[i].handler(eloop.signals[i].sig,
						 eloop.user_data,
						 eloop.signals[i].user_data);
		}
	}
}


int eloop_register_signal(int sig, eloop_signal_handler handler,
			  void *user_data)
{
	struct eloop_signal *tmp;

	tmp = (struct eloop_signal *)
		realloc(eloop.signals,
			   (eloop.signal_count + 1) *
			   sizeof(struct eloop_signal));
	if (tmp == NULL)
		return -1;

	tmp[eloop.signal_count].sig = sig;
	tmp[eloop.signal_count].user_data = user_data;
	tmp[eloop.signal_count].handler = handler;
	tmp[eloop.signal_count].signaled = 0;
	eloop.signal_count++;
	eloop.signals = tmp;
	signal(sig, eloop_handle_signal);

	return 0;
}


int eloop_register_signal_terminate(eloop_signal_handler handler,
				    void *user_data)
{
	int ret = eloop_register_signal(SIGINT, handler, user_data);
	if (ret == 0)
		ret = eloop_register_signal(SIGTERM, handler, user_data);
	return ret;
}


int eloop_register_signal_reconfig(eloop_signal_handler handler,
				   void *user_data)
{
	return eloop_register_signal(SIGHUP, handler, user_data);
}

static inline int os_time_to_ms(struct os_time *tv)
{
	return ((tv)->sec * 1000 + (tv)->usec / 1000);
}

void eloop_run(void)
{
	int res, timeout = 0;
	struct os_time tv, now;
	struct pollfd *fds = NULL;

	while (!eloop.terminate &&
	       (eloop.timeout || eloop.sock_table.count > 0)) {
		if (eloop.timeout) {
			os_get_time(&now);
			if (os_time_before(&now, &eloop.timeout->time))
				os_time_sub(&eloop.timeout->time, &now, &tv);
			else
				tv.sec = tv.usec = 0;
			timeout = os_time_to_ms(&tv);
		}

		fds = (struct pollfd *)
			realloc(fds, eloop.sock_table.count * sizeof(struct eloop_sock));
		if (fds == NULL) {
			perror("eloop_run realloc");
			goto out;
		}

		eloop_sock_table_set_fds(&eloop.sock_table, fds);
		res = poll(fds, eloop.sock_table.count, eloop.timeout ? timeout : -1);
		if (res < 0 && errno != EINTR && errno != 0) {
			perror("poll");
			goto out;
		}
		eloop_process_pending_signals();

		/* check if some registered timeouts have occurred */
		if (eloop.timeout) {
			struct eloop_timeout *tmp;

			os_get_time(&now);
			if (!os_time_before(&now, &eloop.timeout->time)) {
				tmp = eloop.timeout;
				eloop.timeout = eloop.timeout->next;
				tmp->handler(tmp->eloop_data,
					     tmp->user_data);
				free(tmp);
			}

		}

		if (res <= 0)
			continue;
		eloop_sock_table_dispatch(&eloop.sock_table, fds, POLLIN);
	}
out:
	free(fds);
}


void eloop_terminate(int sig, UNUSED void *eloop_ctx, UNUSED void *signal_ctx)
{
	printf("Signal %d received - terminating\n", sig);
	eloop.terminate = 1;
}

void eloop_destroy(void)
{
	struct eloop_timeout *timeout, *prev;

	timeout = eloop.timeout;
	while (timeout != NULL) {
		prev = timeout;
		timeout = timeout->next;
		free(prev);
	}
	eloop_sock_table_destroy(&eloop.sock_table);
	free(eloop.signals);
}


int eloop_terminated(void)
{
	return eloop.terminate;
}


void eloop_wait_for_read_sock(int sock)
{
	struct pollfd pfd;

	if (sock < 0)
		return;

	pfd.fd = sock;
	pfd.events = POLLIN;
	poll(&pfd, 1, -1);
}


void * eloop_get_user_data(void)
{
	return eloop.user_data;
}
