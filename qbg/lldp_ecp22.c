/******************************************************************************

  Implementation of ECP according to 802.1Qbg
  (c) Copyright IBM Corp. 2010, 2012

  Author(s): Jens Osterkamp <jens at linux.vnet.ibm.com>
  Author(s): Thomas Richter <tmricht at linux.vnet.ibm.com>

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

******************************************************************************/

#include <stdio.h>
#include <assert.h>
#include <sys/socket.h>

#include "eloop.h"
#include "lldp_ecp22.h"
#include "messages.h"
#include "lldp_ecp_utils.h"
#include "lldp/l2_packet.h"
#include "lldp_tlv.h"

static const char *ecp22_rx_states[] = {	/* Receive states verbatim */
	"ECP22_RX_BEGIN",
	"ECP22_RX_WAIT",
	"ECP22_RX_WAIT2",
	"ECP22_RX_FIRST",
	"ECP22_RX_REC_ECPDU",
	"ECP22_RX_NEW_ECPDU",
	"ECP22_RX_SEND_ACK"
};

/*
 * Find the ecp data associated with an interface.
 * Return pointer or NULL if not found.
 */
static struct ecp22 *find_ecpdata(char *ifname, struct ecp22_user_data *eud)
{
	struct ecp22 *ecp = 0;

	if (eud) {
		LIST_FOREACH(ecp, &eud->head, node)
			if (!strncmp(ifname, ecp->ifname, IFNAMSIZ))
				break;
	}
	return ecp;
}

/*
 * ecp22_txframe - transmit ecp frame
 * @ecp: pointer to currently used ecp data structure
 *
 * returns the number of characters sent on success, -1 on failure
 *
 * sends out the frame stored in the frame structure using l2_packet_send.
 */
static int ecp22_txframe(struct ecp22 *ecp, unsigned char *dst,
		       unsigned char *ack, size_t len)
{
	ecp_print_frame(ecp->ifname, "frame-ack", ack, len);
	return l2_packet_send(ecp->l2, dst, htons(ETH_P_ECP22), ack, len);
}

/*
 * ecp22_rx_change_state - changes the ecp rx sm state
 * @ecp: pointer to currently used ecp data structure
 * @newstate: new state for the sm
 *
 * no return value
 *
 * checks state transistion for consistency and finally changes the state of
 * the ecp receive buffer.
 */
static void ecp22_rx_change_state(struct ecp22 *ecp, u8 newstate)
{
	switch (newstate) {
	case ECP22_RX_BEGIN:
		break;
	case ECP22_RX_WAIT:
		assert(ecp->rx.state == ECP22_RX_BEGIN);
		break;
	case ECP22_RX_FIRST:
		assert(ecp->rx.state == ECP22_RX_WAIT);
		break;
	case ECP22_RX_REC_ECPDU:
		assert((ecp->rx.state == ECP22_RX_FIRST) ||
		       (ecp->rx.state == ECP22_RX_WAIT2));
		break;
	case ECP22_RX_NEW_ECPDU:
		assert(ecp->rx.state == ECP22_RX_REC_ECPDU);
		break;
	case ECP22_RX_SEND_ACK:
		assert((ecp->rx.state == ECP22_RX_REC_ECPDU) ||
		       (ecp->rx.state == ECP22_RX_NEW_ECPDU));
		break;
	case ECP22_RX_WAIT2:
		assert(ecp->rx.state == ECP22_RX_SEND_ACK);
		break;
	default:
		LLDPAD_ERR("%s:%s LLDP RX state machine invalid state %d\n",
			   __func__, ecp->ifname, newstate);
	}
	LLDPAD_DBG("%s:%s state change %s -> %s\n", __func__,
		   ecp->ifname, ecp22_rx_states[ecp->rx.state],
		   ecp22_rx_states[newstate]);
	ecp->rx.state = newstate;
}

/*
 * Execute action is state sendack. Construct and send an acknowledgement
 * for the received ECP packet.
 */
static void ecp22_es_send_ack(struct ecp22 *ecp)
{
	unsigned char ack_frame[ETH_HLEN + sizeof(struct ecp22_hdr)];
	struct ethhdr *ethdst = (struct ethhdr *)ack_frame;
	struct ecp22_hdr *ecpdst = (struct ecp22_hdr *)&ack_frame[ETH_HLEN];
	struct ethhdr *ethsrc = (struct ethhdr *)ecp->rx.frame;
	struct ecp22_hdr *ecpsrc = (struct ecp22_hdr *)&ecp->rx.frame[ETH_HLEN];
	struct ecp22_hdr ack;

	LLDPAD_DBG("%s:%s state %s seqno %#hx\n", __func__, ecp->ifname,
		   ecp22_rx_states[ecp->rx.state], ecp->rx.seqno);
	/*
	 * Set Ethernet header
	 * TODO: Which mac address to use in ack package
	 * memcpy(ethdst->h_dest, nearest_customer_bridge, ETH_ALEN);
	 */
	memcpy(ethdst->h_dest, ethsrc->h_source, ETH_ALEN);
	l2_packet_get_own_src_addr(ecp->l2, (u8 *)&ethdst->h_source);
	ethdst->h_proto = ethsrc->h_proto;
	/* Set ECP header */
	ack.ver_op_sub = ntohs(ecpsrc->ver_op_sub);
	ecp22_hdr_set_op(&ack, ECP22_ACK);
	ecpdst->ver_op_sub = htons(ack.ver_op_sub);
	ecpdst->seqno = htons(ecp->rx.seqno);
	ecp22_txframe(ecp, ethsrc->h_source, ack_frame, sizeof ack_frame);
}

/*
 * Execute action is state newECPDU.
 */
static void ecp22_es_new_ecpdu(struct ecp22 *ecp)
{
	LLDPAD_DBG("%s:%s state %s notify ULP seqno %#hx\n", __func__,
		   ecp->ifname, ecp22_rx_states[ecp->rx.state], ecp->rx.seqno);
	ecp->rx.last_seqno = ecp->rx.seqno;
}

/*
 * Execute action is state receiveECPDU.
 */
static void ecp22_es_rec_ecpdu(struct ecp22 *ecp)
{
	struct ecp22_hdr *hdr = (struct ecp22_hdr *)&ecp->rx.frame[ETH_HLEN];

	ecp->rx.seqno = ntohs(hdr->seqno);
	LLDPAD_DBG("%s:%s state %s seqno %#hx\n", __func__, ecp->ifname,
		   ecp22_rx_states[ecp->rx.state], ecp->rx.seqno);
}

/*
 * Execute action is state receiveFirst.
 */
static void ecp22_es_first(struct ecp22 *ecp)
{
	struct ecp22_hdr *hdr = (struct ecp22_hdr *)&ecp->rx.frame[ETH_HLEN];

	LLDPAD_DBG("%s:%s state %s\n", __func__, ecp->ifname,
			ecp22_rx_states[ecp->rx.state]);
	ecp->rx.last_seqno = ntohs(hdr->seqno) - 1;
}

/*
 * Execute action is state receiveWait.
 */
static void ecp22_es_wait(struct ecp22 *ecp)
{
	LLDPAD_DBG("%s:%s state %s\n", __func__, ecp->ifname,
			ecp22_rx_states[ecp->rx.state]);
	ecp->rx.ecpdu_received = false;
}

/*
 * ecp22_set_rx_state - sets the ecp receive state machine state
 * @ecp: pointer to currently used ecp data structure
 *
 * returns true or false
 *
 * switches the state machine to the next state depending on the input
 * variables. Returns true or false depending on wether the state machine
 * can be run again with the new state or can stop at the current state.
 */
static bool ecp22_set_rx_state(struct ecp22 *ecp)
{
	struct port *port = port_find_by_name(ecp->ifname);

	if (!port)
		return false;

	LLDPAD_DBG("%s:%s state %s\n", __func__, ecp->ifname,
			   ecp22_rx_states[ecp->rx.state]);
	if (port->portEnabled == false)
		ecp22_rx_change_state(ecp, ECP22_RX_BEGIN);
	switch (ecp->rx.state) {
	case ECP22_RX_BEGIN:
		ecp22_rx_change_state(ecp, ECP22_RX_WAIT);
		return false;
	case ECP22_RX_WAIT:
		if (ecp->rx.ecpdu_received) {
			ecp22_rx_change_state(ecp, ECP22_RX_FIRST);
			return true;
		}
		return false;
	case ECP22_RX_WAIT2:
		if (ecp->rx.ecpdu_received) {
			ecp22_rx_change_state(ecp, ECP22_RX_REC_ECPDU);
			return true;
		}
		return false;
	case ECP22_RX_FIRST:
		ecp22_rx_change_state(ecp, ECP22_RX_REC_ECPDU);
		return true;
	case ECP22_RX_REC_ECPDU:
		if (ecp->rx.seqno == ecp->rx.last_seqno)
			ecp22_rx_change_state(ecp, ECP22_RX_SEND_ACK);
		else
			ecp22_rx_change_state(ecp, ECP22_RX_NEW_ECPDU);
		return true;
	case ECP22_RX_NEW_ECPDU:
		ecp22_rx_change_state(ecp, ECP22_RX_SEND_ACK);
		return true;
	case ECP22_RX_SEND_ACK:
		ecp22_rx_change_state(ecp, ECP22_RX_WAIT2);
		return true;
	default:
		LLDPAD_DBG("%s:%s ECP RX state machine in invalid state %d\n",
			   __func__, ecp->ifname, ecp->rx.state);
		return false;
	}
}

/*
 * ecp22_rx_run_sm - state machine for ecp receive protocol
 * @ecp: pointer to currently used ecp data structure
 *
 * no return value
 *
 * runs the state machine for ecp22 receive function.
 */
static void ecp22_rx_run_sm(struct ecp22 *ecp)
{
	ecp22_set_rx_state(ecp);
	do {
		switch (ecp->rx.state) {
		case ECP22_RX_WAIT:
		case ECP22_RX_WAIT2:
			ecp22_es_wait(ecp);
			break;
		case ECP22_RX_FIRST:
			ecp22_es_first(ecp);
			break;
		case ECP22_RX_REC_ECPDU:
			ecp22_es_rec_ecpdu(ecp);
			break;
		case ECP22_RX_NEW_ECPDU:
			ecp22_es_new_ecpdu(ecp);
			break;
		case ECP22_RX_SEND_ACK:
			ecp22_es_send_ack(ecp);
			break;
		default:
			LLDPAD_DBG("%s:%s ECP RX state machine in invalid "
				   "state %d\n", __func__, ecp->ifname,
				   ecp->rx.state);
		}
	} while (ecp22_set_rx_state(ecp) == true);
}

/*
 * ecp22_rx_receiveframe - receive am ecp frame
 * @ctx: rx callback context, struct ecp * in this case
 * @ifindex: index of interface
 * @buf: buffer which contains the frame just received
 * @len: size of buffer (frame)
 *
 * no return value
 *
 * creates a local copy of the buffer and checks the header. keeps some
 * statistics about ecp frames. Checks if it is a request or an ack frame and
 * branches to ecp rx or ecp tx state machine.
 */
static void ecp22_rx_receiveframe(void *ctx, int ifindex, const u8 *buf,
				  size_t len)
{
	struct ecp22 *ecp = (struct ecp22 *)ctx;
	struct port *port;
	struct ecp22_hdr *ecp_hdr, ecphdr;

	LLDPAD_DBG("%s:%s ifindex:%d len:%zd state:%s ecpdu_received:%d\n",
		   __func__, ecp->ifname, ifindex, len,
		   ecp22_rx_states[ecp->rx.state], ecp->rx.ecpdu_received);
	ecp_print_frame(ecp->ifname, "frame-in", buf, len);
	port = port_find_by_name(ecp->ifname);
	if (!port || ecp->rx.ecpdu_received)
		/* Port not found or buffer not free */
		return;

	memcpy(ecp->rx.frame, buf, len);
	ecp->rx.frame_len = len;
	ecp->stats.statsFramesInTotal++;

	ecp_hdr = (struct ecp22_hdr *)&ecp->rx.frame[ETH_HLEN];
	ecphdr.ver_op_sub = ntohs(ecp_hdr->ver_op_sub);

	switch (ecp22_hdr_read_op(&ecphdr)) {
	case ECP22_REQUEST:
		LLDPAD_DBG("%s:%s received REQ frame seqno %#hx\n", __func__,
			   ecp->ifname, ntohs(ecp_hdr->seqno));
		ecp->rx.ecpdu_received = true;
		ecp22_rx_run_sm(ecp);
		break;
	case ECP22_ACK:
		LLDPAD_DBG("%s:%s received ACK frame seqno %#hx\n", __func__,
			   ecp->ifname, ntohs(ecp_hdr->seqno));
		break;
	default:
		LLDPAD_ERR("%s:%s ERROR unknown mode %#02hx seqno %#hx\n",
			   __func__, ecp->ifname, ecphdr.ver_op_sub,
			   ntohs(ecp_hdr->seqno));
	}
}

/*
 * ecp22_create - create data structure and initialize ecp protocol
 * @ifname: interface for which the ecp protocol is initialized
 *
 * returns NULL on error and an pointer to the ecp22 structure on success.
 *
 * finds the port to the interface name, sets up the receive handle for
 * incoming ecp frames and initializes the ecp rx and tx state machines.
 * To be called when a successful exchange of EVB TLVs has been
 * made and ECP protocols are supported by both sides.
 */
static struct ecp22 *ecp22_create(char *ifname, struct ecp22_user_data *eud)
{
	struct ecp22 *ecp;

	ecp = calloc(1, sizeof *ecp);
	if (!ecp) {
		LLDPAD_ERR("%s:%s unable to allocate ecp protocol\n", __func__,
			   ifname);
		return NULL;
	}
	strncpy(ecp->ifname, ifname, sizeof ecp->ifname);
	ecp->l2 = l2_packet_init(ecp->ifname, 0, ETH_P_ECP22,
				 ecp22_rx_receiveframe, ecp, 1);

	if (!ecp->l2) {
		LLDPAD_ERR("%s:%s error open layer 2 ETH_P_ECP\n", __func__,
			   ifname);
		free(ecp);
		return NULL;
	}
	LIST_INSERT_HEAD(&eud->head, ecp, node);
	LLDPAD_DBG("%s:%s create ecp data\n", __func__, ifname);
	return ecp;
}

/*
 * ecp22_start - build up ecp structures for an interface
 * @ifname: name of the interface
 */
void ecp22_start(char *ifname)
{
	struct ecp22_user_data *eud;
	struct ecp22 *ecp;

	LLDPAD_DBG("%s:%s start ecp\n", __func__, ifname);
	eud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_ECP22);
	if (!eud) {
		LLDPAD_DBG("%s:%s no ECP module\n", __func__, ifname);
		return;
	}
	ecp = find_ecpdata(ifname, eud);
	if (!ecp)
		ecp = ecp22_create(ifname, eud);
	LIST_INIT(&ecp->inuse.head);
	ecp->inuse.last = 0;
	LIST_INIT(&ecp->isfree.head);
	ecp->isfree.freecnt = 0;
	ecp->rx.state = ECP22_RX_BEGIN;
	ecp22_rx_run_sm(ecp);
}

/*
 * Remove the ecp_payload nodes
 */
static void ecp22_removelist(ecp22_list *ptr)
{
	struct ecp22_payload_node *np;

	while ((np = LIST_FIRST(ptr))) {
		LIST_REMOVE(np, node);
		np->ptlv = free_pkd_tlv(np->ptlv);
		free(np);
	}
}

static void ecp22_remove(struct ecp22 *ecp)
{
	LLDPAD_DBG("%s:%s remove ecp\n", __func__, ecp->ifname);
	ecp22_removelist(&ecp->inuse.head);
	ecp->inuse.last = 0;
	ecp22_removelist(&ecp->isfree.head);
	ecp->isfree.freecnt = 0;
	LIST_REMOVE(ecp, node);
	free(ecp);
}

/*
 * ecp22_stop - tear down ecp structures for a interface
 * @ifname: name of the interface
 *
 * no return value
 *
 */
void ecp22_stop(char *ifname)
{
	struct ecp22_user_data *eud;
	struct ecp22 *ecp;

	LLDPAD_DBG("%s:%s stop ecp\n", __func__, ifname);
	eud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_ECP22);
	ecp = find_ecpdata(ifname, eud);
	if (ecp)
		ecp22_remove(ecp);
}

static const struct lldp_mod_ops ecp22_ops =  {
	.lldp_mod_register = ecp22_register,
	.lldp_mod_unregister = ecp22_unregister
};

/*
 * ecp22_register - register ecp module to lldpad
 *
 * returns lldp_module struct on success, NULL on error
 *
 * allocates a module structure with ecp module information and returns it
 * to lldpad.
 */
struct lldp_module *ecp22_register(void)
{
	struct lldp_module *mod;
	struct ecp22_user_data *eud;

	mod = calloc(1, sizeof *mod);
	if (!mod) {
		LLDPAD_ERR("%s:can not allocate ecp module data\n", __func__);
		return NULL;
	}
	eud = calloc(1, sizeof(struct ecp22_user_data));
	if (!eud) {
		free(mod);
		LLDPAD_ERR("%s:can not allocate ecp user data\n", __func__);
		return NULL;
	}
	LIST_INIT(&eud->head);
	mod->id = LLDP_MOD_ECP22;
	mod->ops = &ecp22_ops;
	mod->data = eud;
	LLDPAD_DBG("%s: done\n", __func__);
	return mod;
}

/*
 * ecp22_free_data - frees up ecp data chain
 */
static void ecp22_free_data(struct ecp22_user_data *ud)
{
	struct ecp22 *ecp;

	if (ud) {
		while (!LIST_EMPTY(&ud->head)) {
			ecp = LIST_FIRST(&ud->head);
			ecp22_remove(ecp);
		}
	}
}

/*
 * ecp22_unregister - unregister ecp module from lldpad
 *
 * no return value
 *
 * frees ecp module structure and user data.
 */
void ecp22_unregister(struct lldp_module *mod)
{
	if (mod->data) {
		ecp22_free_data((struct ecp22_user_data *)mod->data);
		free(mod->data);
	}
	free(mod);
	LLDPAD_DBG("%s: done\n", __func__);
}
