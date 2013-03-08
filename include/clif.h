/*******************************************************************************

  LLDP Agent Daemon (LLDPAD) Software 
  Copyright(c) 2007-2012 Intel Corporation.

  Substantially modified from:
  hostapd-0.5.7
  Copyright (c) 2002-2007, Jouni Malinen <jkmaline@cc.hut.fi> and
  contributors

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  open-lldp Mailing List <lldp-devel@open-lldp.org>

*******************************************************************************/

#ifndef CLIF_H
#define CLIF_H

#include <sys/un.h>
#include "clif_sock.h"

/**
 * struct clif - Internal structure for client interface library
 *
 * This structure is used by the lldpad client interface
 * library to store internal data. Programs using the library should not touch
 * this data directly. They can only use the pointer to the data structure as
 * an identifier for the client interface connection and use this as one of
 * the arguments for most of the client interface library functions.
 */
struct clif {
	int s;
	struct sockaddr_un local;
	struct sockaddr_un dest;
};

/* lldpad client interface access */

/**
 * clif_open - Open a client interface to the lldpad
 * Returns: Pointer to abstract client interface data or %NULL on failure
 *
 * This function is used to open a client interface to the lldpad.
 */
struct clif *clif_open(void);


/**
 * clif_close - Close a client interface to lldpad
 * @clif: Control interface data from clif_open()
 *
 * This function is used to close a client interface.
 */
void clif_close(struct clif *clif);


/**
 * clif_request - Send a command to lldpad
 * @clif: Control interface data from clif_open()
 * @cmd: Command; usually, ASCII text, e.g., "PING"
 * @cmd_len: Length of the cmd in bytes
 * @reply: Buffer for the response
 * @reply_len: Reply buffer length
 * @msg_cb: Callback function for unsolicited messages or %NULL if not used
 * Returns: 0 on success, -1 on error (send or receive failed), -2 on timeout
 *
 * This function is used to send commands to lldpad. Received
 * response will be written to reply and reply_len is set to the actual length
 * of the reply. This function will block for up to two seconds while waiting
 * for the reply. If unsolicited messages are received, the blocking time may
 * be longer.
 *
 * msg_cb can be used to register a callback function that will be called for
 * unsolicited messages received while waiting for the command response. These
 * messages may be received if clif_request() is called at the same time as
 * lldpad is sending such a message. This can happen only if
 * the program has used clif_attach() to register itself as a monitor for
 * event messages. Alternatively to msg_cb, programs can register two client
 * interface connections and use one of them for commands and the other one for
 * receiving event messages, in other words, call clif_attach() only for
 * the client interface connection that will be used for event messages.
 */
#define CMD_RESPONSE_TIMEOUT 2
int clif_request(struct clif *clif, const char *cmd, size_t cmd_len,
		     char *reply, size_t *reply_len,
		     void (*msg_cb)(char *msg, size_t len));


/**
 * clif_attach - Register as an event monitor for the client interface
 * @clif: Control interface data from clif_open()
 * Returns: 0 on success, -1 on failure, -2 on timeout
 *
 * This function registers the client interface connection as a monitor for
 * lldpad events. After a success clif_attach() call, the
 * client interface connection starts receiving event messages that can be
 * read with clif_recv().
 */
int clif_attach(struct clif *clif, char *hex_tlvs);


/**
 * clif_detach - Unregister event monitor from the client interface
 * @clif: Control interface data from clif_open()
 * Returns: 0 on success, -1 on failure, -2 on timeout
 *
 * This function unregisters the client interface connection as a monitor for
 * lldpad events, i.e., cancels the registration done with
 * clif_attach().
 */
int clif_detach(struct clif *clif);


/**
 * clif_recv - Receive a pending client interface message
 * @clif: Control interface data from clif_open()
 * @reply: Buffer for the message data
 * @reply_len: Length of the reply buffer
 * Returns: 0 on success, -1 on failure
 *
 * This function will receive a pending client interface message. This
 * function will block if no messages are available. The received response will
 * be written to reply and reply_len is set to the actual length of the reply.
 * clif_recv() is only used for event messages, i.e., clif_attach()
 * must have been used to register the client interface as an event monitor.
 */
int clif_recv(struct clif *clif, char *reply, size_t *reply_len);


/**
 * clif_pending - Check whether there are pending event messages
 * @clif: Control interface data from clif_open()
 * Returns: 1 if there are pending messages, 0 if no, or -1 on error
 *
 * This function will check whether there are any pending client interface
 * message available to be received with clif_recv(). clif_pending() is
 * only used for event messages, i.e., clif_attach() must have been used to
 * register the client interface as an event monitor.
 */
int clif_pending(struct clif *clif);


/**
 * clif_get_fd - Get file descriptor used by the client interface
 * @clif: Control interface data from clif_open()
 * Returns: File descriptor used for the connection
 *
 * This function can be used to get the file descriptor that is used for the
 * client interface connection. The returned value can be used, e.g., with
 * select() while waiting for multiple events.
 *
 * The returned file descriptor must not be used directly for sending or
 * receiving packets; instead, the library functions clif_request() and
 * clif_recv() must be used for this.
 */
int clif_get_fd(struct clif *clif);

/**
 * clif_getpid - Get PID of running lldpad process
 * Returns: The PID of lldpad or 0 on failure
 *
 * This function is returns the PID of the running lldpad. It connects to the
 * lldpad and sends a PING command. Lldpad returns with a PONG followed by
 * its PID. Extract the PID and return it to the caller.
 */
pid_t clif_getpid(void);
#endif /* CLIF_H */
