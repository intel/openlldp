/******************************************************************************

  Implementation of VDP 2.2 bridge and station state machines for
  IEEE 802.1 Qbg ratified standard.
  (c) Copyright IBM Corp. 2013

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

/*
 * Implement the IEEE 802.1Qbg ratified standard VDP Protocol state machines.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <net/if.h>
#include <netinet/in.h>

#include "messages.h"
#include "config.h"
#include "eloop.h"

#include "qbg22.h"
#include "qbg_vdp22.h"
#include "qbg_utils.h"

/*
 * Set status code
 */
static inline unsigned char make_status(int x)
{
	return (x << VDP22_STATUS_SHIFT) & VDP22_STATUS_MASK;
}

enum vdp22br_states {		/* State for VDP22 bridge processing */
	VDP22_BR_START = 100,	/* Start state */
	VDP22_BR_BEGIN,		/* Begin state */
	VDP22_BR_INIT,		/* Init state */
	VDP22_BR_PROCESS,	/* Process command from station */
	VDP22_BR_SEND,		/* Send result to station */
	VDP22_BR_WAITCMD,	/* Wait for cmd from station */
	VDP22_BR_WAITCMD_2,	/* End of wait for cmd from station */
	VDP22_BR_KEEP,		/* Send keep result to station */
	VDP22_BR_DEASSOC,	/* Send de-assoc result to station */
	VDP22_BR_ALIVE,		/* Process keep alive from station state */
	VDP22_BR_DEASSOCIATED,	/* Deassoc state */
	VDP22_BR_END		/* End state */
};

/* VDP22 bridge states verbatim */
static const char *const vdp22br_states_n[] = {
	"unknown",
	"VDP22_BR_BEGIN",
	"VDP22_BR_INIT",
	"VDP22_BR_PROCESS",
	"VDP22_BR_SEND",
	"VDP22_BR_WAITCMD",
	"VDP22_BR_WAITCMD_2",
	"VDP22_BR_KEEP",
	"VDP22_BR_DEASSOC",
	"VDP22_BR_ALIVE",
	"VDP22_BR_DEASSOCIATED",
	"VDP22_BR_END"
};

static inline const char *vdp22br_state_name(enum vdp22br_states x)
{
	return vdp22br_states_n[x - VDP22_BR_START];
}

enum vdp22_states {		/* VDP22 station states */
	VDP22_BEGIN = 1,
	VDP22_INIT,
	VDP22_STATION_PROC,	/* Station processing */
	VDP22_STATION_PROCWAIT,	/* Station processing, wait for reply */
	VDP22_STATION_PROCWAIT_2,	/* Station processing, received reply */
	VDP22_ASSOC_NEW,
	VDP22_ASSOC_COMPL,	/* Assoc complete */
	VDP22_PREASSOC_NEW,
	VDP22_WAIT_SYSCMD,
	VDP22_WAIT_SYSCMD_2,
	VDP22_TXMIT_KA,		/* Transmit keep alive */
	VDP22_TXMIT_KAWAIT,	/* Transmit keep alive, wait for reply */
	VDP22_TXMIT_KAWAIT_2,	/* Transmit keep alive, received message */
	VDP22_TXMIT_DEASSOC,	/* Transmit Deassociation */
	VDP22_TXMIT_DEAWAIT,	/* Transmit Deassociation, wait for reply */
	VDP22_TXMIT_DEAWAIT_2,	/* Transmit Deassociation, received reply */
	VDP22_END
};

/* VDP22 station states verbatim */
static const char *const vdp22_states_n[] = {
	"unknown",
	"VDP22_BEGIN",
	"VDP22_INIT",
	"VDP22_STATION_PROC",
	"VDP22_STATION_PROCWAIT",
	"VDP22_STATION_PROCWAIT_2",
	"VDP22_ASSOC_NEW",
	"VDP22_ASSOC_COMPL",
	"VDP22_PREASSOC_NEW",
	"VDP22_WAIT_SYSCMD",
	"VDP22_WAIT_SYSCMD_2",
	"VDP22_TXMIT_KA",
	"VDP22_TXMIT_KAWAIT",
	"VDP22_TXMIT_KAWAIT_2",
	"VDP22_TXMIT_DEASSOC",
	"VDP22_TXMIT_DEAWAIT",
	"VDP22_TXMIT_DEAWAIT_2",
	"VDP22_END"
};

/*
 * Forward definition of function prototypes.
 */
static void vdp22st_run(struct vsi22 *);
static void vdp22br_run(struct vsi22 *);
static void vdp22_station_info(struct vsi22 *);

/*
 * Return size of packed and unpacked VSI tlv.
 */
static inline size_t mgr22_tlv_sz(void)
{
	return 16;
}

static inline size_t mgr22_ptlv_sz(void)
{
	return 2 + mgr22_tlv_sz();
}

/* Return size for each filter data format */
static inline size_t vsi22_fdata_sz(unsigned char fif)
{
	switch (fif) {
	case VDP22_FFMT_VID:
		return 2;
	case VDP22_FFMT_MACVID:
		return 8;
	case VDP22_FFMT_GROUPVID:
		return 6;
	case VDP22_FFMT_GROUPMACVID:
		return 12;
	}
	return 0;
}

static inline size_t vsi22_tlv_fifsz(struct vsi22 *vp)
{
	return vp->no_fdata * vsi22_fdata_sz(vp->fif);
}

static inline size_t vsi22_tlv_sz(struct vsi22 *vp)
{
	return 23 + 2 + vsi22_tlv_fifsz(vp);
}

static inline size_t vsi22_ptlv_sz(struct vsi22 *vp)
{
	return 2 + vsi22_tlv_sz(vp);
}

/*
 * Extract 1, 2, 3, 4 byte integers in network byte format.
 * Extract n bytes.
 * Assume enough space available.
 * Return number of bytes extracted.
 */
static inline size_t extract_1o(unsigned char *data, const unsigned char *cp)
{
	*data = *cp;
	return 1;
}

static inline size_t extract_2o(unsigned short *data, const unsigned char *cp)
{
	*data = (*cp << 8) | *(cp + 1);
	return 2;
}

static inline size_t extract_3o(unsigned long *data, const unsigned char *cp)
{
	*data = (*cp << 16) | (*(cp + 1) << 8) | *(cp + 2);
	return 3;
}

static inline size_t extract_4o(unsigned long *data, const unsigned char *cp)
{
	*data = (*cp << 24)  | (*(cp + 1) << 16) | (*(cp + 2) << 8) | *(cp + 3);
	return 4;
}
static inline size_t extract_no(unsigned char *data, const unsigned char *cp,
				const size_t len)
{
	memcpy(data, cp, len);
	return len;
}

/*
 * Append 1, 2, 3, 4 byte integers in network byte format.
 * Append n bytes.
 * Assume enough space available.
 * Return number of bytes written.
 */
static inline size_t append_1o(unsigned char *cp, const unsigned char data)
{
	*cp = data;
	return 1;
}

static inline size_t append_2o(unsigned char *cp, const unsigned short data)
{
	*cp = (data >> 8) & 0xff;
	*(cp + 1) = data & 0xff;
	return 2;
}

static inline size_t append_3o(unsigned char *cp, const unsigned long data)
{
	*cp = (data >> 16) & 0xff;
	*(cp + 1) = (data >> 8) & 0xff;
	*(cp + 2) = data & 0xff;
	return 3;
}

static inline size_t append_4o(unsigned char *cp, const unsigned long data)
{
	*cp = (data >> 24) & 0xff;
	*(cp + 1) = (data >> 16) & 0xff;
	*(cp + 2) = (data >> 8) & 0xff;
	*(cp + 3) = data & 0xff;
	return 4;
}

static inline size_t append_nb(unsigned char *cp, const unsigned char *data,
			       const size_t nlen)
{
	memcpy(cp, data, nlen);
	return nlen;
}

/*
 * Packed TLV header manipulation.
 */
static inline unsigned short ptlv_head(unsigned short type, unsigned short len)
{
	return (type & 0x7f) << 9 | (len & 0x1ff);
}

static inline unsigned short ptlv_length(unsigned short header)
{
	return 2 + (header & 0x1ff);
}

static inline unsigned short ptlv_type(unsigned short header)
{
	return (header >> 9) & 0x7f;
}

/*
 * Build a VSI tlv.
 */
static size_t vsi22_2tlv_fdata(unsigned char *cp, struct fid22 *p,
			       unsigned char fif)
{
	size_t nbytes = 0;

	switch (fif) {
	case VDP22_FFMT_VID:
		nbytes = append_2o(cp, p->vlan);
		break;
	case VDP22_FFMT_MACVID:
		nbytes = append_nb(cp, p->mac, sizeof(p->mac));
		nbytes += append_2o(cp + nbytes, p->vlan);
		break;
	case VDP22_FFMT_GROUPVID:
		nbytes = append_4o(cp, p->grpid);
		nbytes += append_2o(cp + nbytes, p->vlan);
		break;
	case VDP22_FFMT_GROUPMACVID:
		nbytes = append_4o(cp, p->grpid);
		nbytes += append_nb(cp + nbytes, p->mac, sizeof(p->mac));
		nbytes += append_2o(cp + nbytes, p->vlan);
		break;
	}
	return nbytes;
}

static void vsi22_2tlv(struct vsi22 *vp, char unsigned *cp, unsigned char stat)
{
	size_t offset = 0, i;
	unsigned short head = ptlv_head(vp->vsi_mode, vsi22_tlv_sz(vp));

	offset = append_2o(cp, head);
	offset += append_1o(cp + offset, stat);
	offset += append_3o(cp + offset, vp->type_id);
	offset += append_1o(cp + offset, vp->type_ver);
	offset += append_1o(cp + offset, vp->vsi_fmt);
	offset += append_nb(cp + offset, vp->vsi, sizeof(vp->vsi));
	offset += append_1o(cp + offset, vp->fif);
	offset += append_2o(cp + offset, vp->no_fdata);
	for (i = 0; i < vp->no_fdata; ++i)
		offset += vsi22_2tlv_fdata(cp + offset, &vp->fdata[i], vp->fif);
}

static void mgr22_2tlv(struct vsi22 *vp, unsigned char *cp)
{
	unsigned short head = ptlv_head(VDP22_MGRID, mgr22_tlv_sz());
	size_t offset;

	offset = append_2o(cp, head);
	append_nb(cp + offset, vp->mgrid, sizeof(vp->mgrid));
}

/*
 * Code for VSI station state machine
 */
/*
 * VSI ACK time out handler
 */
static void vdp22st_handle_kato(UNUSED void *ctx, void *data)
{
	struct vsi22 *p = data;

	LLDPAD_DBG("%s:%s timeout keep alive timer for %p(%02x)\n",
		   __func__, p->vdp->ifname, p, p->vsi[0]);
	p->smi.kato = true;
	vdp22st_run(p);
}

/*
 * Start the VSI station keep alive timer when a VSI state has been agreed upon.
 */
static int vdp22st_start_katimer(struct vsi22 *p)
{
	unsigned long long towait = (1 << p->vdp->vdp_rka) * 10;
	unsigned int secs, usecs;

	secs = towait / USEC_PER_SEC;
	usecs = towait % USEC_PER_SEC;
	p->smi.kato = false;
	LLDPAD_DBG("%s:%s start keep alive timer for %p(%02x) [%i,%i]\n",
		   __func__, p->vdp->ifname, p, p->vsi[0], secs, usecs);
	return eloop_register_timeout(secs, usecs, vdp22st_handle_kato, NULL,
				      (void *)p);
}

/*
 * Stops the VSI ack timer
 * Returns the number of removed handlers
 */
static int vdp22st_stop_katimer(struct vsi22 *p)
{
	LLDPAD_DBG("%s:%s stop keep alive timer for %p(%02x)\n", __func__,
		   p->vdp->ifname, p, p->vsi[0]);
	return eloop_cancel_timeout(vdp22st_handle_kato, NULL, (void *)p);
}

/*
 * VSI ACK time out handler
 */
static void vdp22st_handle_ackto(UNUSED void *ctx, void *data)
{
	struct vsi22 *p = data;

	LLDPAD_DBG("%s:%s timeout ack timer for %p(%02x) ackreceived:%d\n",
		   __func__, p->vdp->ifname, p, p->vsi[0], p->smi.ackreceived);
	if (!p->smi.ackreceived) {
		p->smi.kato = true;
		vdp22st_run(p);
	}
}

/*
 * Calculate VDP22 keep alive/response wait delay timeout. See 41.5.5.9.
 */
static void vdp22_timeout(struct vdp22 *p, unsigned char exp,
			      unsigned int *secs, unsigned int *usecs)
{
	unsigned long long towait;

	towait = (1 + 2 * p->ecp_retries) * (1 << p->ecp_rte) * 10;
	towait += (1 << exp) * 10;
	towait += towait / 2;
	*secs = towait / USEC_PER_SEC;
	*usecs = towait % USEC_PER_SEC;
}

/*
 * Starts the VPD22 station response wait delay timer. See 41.5.5.9.
 */
static int vdp22st_start_acktimer(struct vsi22 *p)
{
	unsigned int secs, usecs;

	p->smi.txmit = true;
	p->smi.txmit_error = 0;
	p->smi.ackreceived = false;
	p->smi.acktimeout = false;
	p->smi.resp_ok = false;
	p->smi.localchg = false;
	vdp22_timeout(p->vdp, p->vdp->vdp_rwd, &secs, &usecs);
	LLDPAD_DBG("%s:%s start ack timer for %p(%02x) [%i,%i]\n",
		   __func__, p->vdp->ifname, p, p->vsi[0], secs, usecs);
	return eloop_register_timeout(secs, usecs, vdp22st_handle_ackto, NULL,
				      (void *)p);
}

/*
 % Stops the VSI ack timer
 * Returns the number of removed handlers
 */
static int vdp22st_stop_acktimer(struct vsi22 *p)
{
	LLDPAD_DBG("%s:%s stop ack timer for %p(%02x)\n", __func__,
		   p->vdp->ifname, p, p->vsi[0]);
	return eloop_cancel_timeout(vdp22st_handle_ackto, NULL, (void *)p);
}

/*
 * Station init state
 */
static void vdp22st_init(struct vsi22 *vsip)
{
	vsip->smi.state = VDP22_INIT;
	vsip->status = VDP22_RESP_NONE;
}

/*
 * Station association new and complete state
 */
static void vdp22st_assoc_compl(struct vsi22 *vsip)
{
	vsip->flags &= ~VDP22_BUSY;
	vsip->resp_vsi_mode = 0;
}

static void vdp22st_assoc_new(struct vsi22 *vsip, enum vdp22_modes x)
{
	vdp22st_assoc_compl(vsip);
	vsip->cc_vsi_mode = x;
}

/*
 * Station wait system command state
 */
static void vdp22st_wait_syscmd(struct vsi22 *vsip)
{
	vdp22st_start_katimer(vsip);
}

/*
 * Station processing state, send packed tlvs to bridge. Allocate send buffer
 * on stack and create packed TLVs.
 */
static void vdp22st_process(struct vsi22 *vsi)
{
	unsigned short len = mgr22_ptlv_sz() + vsi22_ptlv_sz(vsi);
	unsigned char buf[len];
	struct qbg22_imm qbg;

	qbg.data_type = VDP22_TO_ECP22;
	qbg.u.c.len = len;
	qbg.u.c.data = buf;
	mgr22_2tlv(vsi, buf);
	vsi22_2tlv(vsi, buf + mgr22_ptlv_sz(), vsi->hints);
	vsi->smi.txmit_error = modules_notify(LLDP_MOD_ECP22, LLDP_MOD_VDP22,
					       vsi->vdp->ifname, &qbg);
	if (!vsi->smi.txmit_error) {
		vdp22st_stop_katimer(vsi);	/* Could still be running */
		vdp22st_start_acktimer(vsi);
	}
	LLDPAD_DBG("%s:%s len:%hd rc:%d\n", __func__, vsi->vdp->ifname, len,
		   vsi->smi.txmit_error);
}

/*
 * Station transmit deassociate state.
 */
static void vdp22st_txdea(struct vsi22 *vsip)
{
	vsip->vsi_mode = VDP22_DEASSOC;
	vsip->flags |= VDP22_BUSY;
	vdp22st_process(vsip);
}

/*
 * Station transmit keep alive state.
 */
static void vdp22st_txka(struct vsi22 *vsip)
{
	vdp22st_process(vsip);
}

/*
 * Station remove a VSI from the VDP22 protocol state machine.
 * Notification of clients depends on the interface used to establish the
 * association:
 * 1. When through netlink interface (draft 0.2) the client is polling for some
 *    time. In this case send a netlink message only when no command pending.
 * 2. When through attached client (draft 2.2) the client is waiting for
 *    response (time out in operation on client side) and does not poll.
 */
static void vdp22st_end(struct vsi22 *vsi)
{
	vdp22st_stop_acktimer(vsi);
	vdp22st_stop_katimer(vsi);
	LLDPAD_DBG("%s:%s vsi:%p(%02x) flags:%#lx vsi_mode:%d,%d"
		   " resp_vsi_mode:%d\n", __func__,
		   vsi->vdp->ifname, vsi, vsi->vsi[0], vsi->flags,
		   vsi->vsi_mode, vsi->cc_vsi_mode, vsi->resp_vsi_mode);
	vsi->vsi_mode = vsi->cc_vsi_mode = VDP22_DEASSOC;
	vsi->flags |= VDP22_DELETE_ME;
	vsi->flags &= ~VDP22_BUSY;
	if (vsi->flags & VDP22_NOTIFY)
		vdp22_nlback(vsi);	/* Notify netlink when no cmd pending */
	vdp22_clntback(vsi);		/* Notify attached client */
}

/*
 * Station change into a new state.
 */
static void vdp22st_change_state(struct vsi22 *vsi, enum vdp22_states newstate)
{
	switch (newstate) {
	case VDP22_INIT:
		assert(vsi->smi.state == VDP22_BEGIN);
		break;
	case VDP22_STATION_PROC:
		assert(vsi->smi.state == VDP22_INIT
		       || vsi->smi.state == VDP22_WAIT_SYSCMD_2);
		break;
	case VDP22_STATION_PROCWAIT:
		assert(vsi->smi.state == VDP22_STATION_PROC);
		break;
	case VDP22_STATION_PROCWAIT_2:
		assert(vsi->smi.state == VDP22_STATION_PROCWAIT);
		break;
	case VDP22_PREASSOC_NEW:
		assert(vsi->smi.state == VDP22_STATION_PROCWAIT_2);
		break;
	case VDP22_ASSOC_NEW:
		assert(vsi->smi.state == VDP22_STATION_PROCWAIT_2);
		break;
	case VDP22_ASSOC_COMPL:
		assert(vsi->smi.state == VDP22_ASSOC_NEW
		       || vsi->smi.state == VDP22_STATION_PROCWAIT_2);
		break;
	case VDP22_WAIT_SYSCMD:
		assert(vsi->smi.state == VDP22_ASSOC_COMPL
		       || vsi->smi.state == VDP22_PREASSOC_NEW
		       || vsi->smi.state == VDP22_TXMIT_KAWAIT_2);
		break;
	case VDP22_WAIT_SYSCMD_2:
		assert(vsi->smi.state == VDP22_WAIT_SYSCMD);
		break;
	case VDP22_TXMIT_KA:
		assert(vsi->smi.state == VDP22_WAIT_SYSCMD_2);
		break;
	case VDP22_TXMIT_KAWAIT:
		assert(vsi->smi.state == VDP22_TXMIT_KA);
		break;
	case VDP22_TXMIT_KAWAIT_2:
		assert(vsi->smi.state == VDP22_TXMIT_KAWAIT);
		break;
	case VDP22_TXMIT_DEASSOC:
		assert(vsi->smi.state == VDP22_TXMIT_KAWAIT_2);
		break;
	case VDP22_TXMIT_DEAWAIT:
		assert(vsi->smi.state == VDP22_TXMIT_DEASSOC);
		break;
	case VDP22_TXMIT_DEAWAIT_2:
		assert(vsi->smi.state == VDP22_TXMIT_DEAWAIT);
		break;
	case VDP22_END:
		assert(vsi->smi.state == VDP22_STATION_PROCWAIT
		       || vsi->smi.state == VDP22_STATION_PROCWAIT_2
		       || vsi->smi.state == VDP22_TXMIT_KAWAIT
		       || vsi->smi.state == VDP22_TXMIT_KAWAIT_2
		       || vsi->smi.state == VDP22_WAIT_SYSCMD_2
		       || vsi->smi.state == VDP22_TXMIT_DEASSOC
		       || vsi->smi.state == VDP22_TXMIT_DEAWAIT
		       || vsi->smi.state == VDP22_TXMIT_DEAWAIT_2);
		break;
	default:
		LLDPAD_ERR("%s:%s VDP station machine INVALID STATE %d\n",
			   __func__, vsi->vdp->ifname, newstate);
	}
	LLDPAD_DBG("%s:%s state change %s -> %s\n", __func__,
		   vsi->vdp->ifname, vdp22_states_n[vsi->smi.state],
		   vdp22_states_n[newstate]);
	vsi->smi.state = newstate;
}

/*
 * Check for hard and soft errors.
 */
static inline bool bad_error(unsigned char x)
{
	return (x && (x & VDP22_KEEPBIT) == 0) ? true : false;
}

static inline bool keep_error(unsigned char x)
{
	return (x && (x & VDP22_KEEPBIT)) ? true : false;
}

/*
 * Return error code. Check for HARDBIT/KEEPBIT set and no error code.
 */
static inline unsigned char get_error(unsigned char x)
{
	return (x & VDP22_STATUS_MASK) ? x & ~(VDP22_RESBIT|VDP22_ACKBIT) : 0;
}

/*
 * vdp22st_move_state - advances the VDP station state machine state
 *
 * Switches the state machine to the next state depending on the input
 * variables. returns true or false depending on wether the state machine
 * can be run again with the new state or can stop at the current state.
 */
static bool vdp22st_move_state(struct vsi22 *vsi)
{
	enum vdp22_states newstate;

	LLDPAD_DBG("%s:%s state %s\n", __func__, vsi->vdp->ifname,
		   vdp22_states_n[vsi->smi.state]);
	switch (vsi->smi.state) {
	case VDP22_BEGIN:
		vdp22st_change_state(vsi, VDP22_INIT);
		return true;
	case VDP22_INIT:
		vdp22st_change_state(vsi, VDP22_STATION_PROC);
		return true;
	case VDP22_STATION_PROC:
		vdp22st_change_state(vsi, VDP22_STATION_PROCWAIT);
		return true;
	case VDP22_STATION_PROCWAIT:
		if (vsi->smi.txmit_error || vsi->smi.acktimeout) {
			/* Error handover to ECP22 or no VDP22 ack */
			vdp22st_change_state(vsi, VDP22_END);
			return true;
		}
		if (vsi->smi.ackreceived) {
			vdp22st_change_state(vsi, VDP22_STATION_PROCWAIT_2);
			return true;
		}
		return false;
	case VDP22_STATION_PROCWAIT_2:
		if (!vsi->smi.resp_ok		/* Mismatch in response */
		    || bad_error(vsi->status)) {	/* Error without KEEP */
			vdp22st_change_state(vsi, VDP22_END);
			return true;
		}
		if (keep_error(vsi->status)) {	/* Error with KEEP on */
			if (vsi->resp_vsi_mode == VDP22_ASSOC)
				newstate = VDP22_ASSOC_COMPL;
			else
				newstate = VDP22_END;
		} else if (vsi->resp_vsi_mode == VDP22_PREASSOC
			   || vsi->resp_vsi_mode == VDP22_PREASSOC_WITH_RR)
			newstate = VDP22_PREASSOC_NEW;
		else if (vsi->resp_vsi_mode == VDP22_DEASSOC)
			newstate = VDP22_END;
		else
			newstate = VDP22_ASSOC_NEW;
		vdp22st_change_state(vsi, newstate);
		return true;
	case VDP22_ASSOC_NEW:
		vdp22st_change_state(vsi, VDP22_ASSOC_COMPL);
		return true;
	case VDP22_ASSOC_COMPL:
	case VDP22_PREASSOC_NEW:
		vdp22st_change_state(vsi, VDP22_WAIT_SYSCMD);
		return true;
	case VDP22_WAIT_SYSCMD:
		vdp22st_change_state(vsi, VDP22_WAIT_SYSCMD_2);
		return true;
	case VDP22_WAIT_SYSCMD_2:
		if (vsi->smi.kato) {
			vdp22st_change_state(vsi, VDP22_TXMIT_KA);
			return true;
		}
		if (vsi->smi.localchg) {
			vdp22st_change_state(vsi, VDP22_STATION_PROC);
			return true;
		}
		if (vsi->smi.deassoc) {
			vdp22st_change_state(vsi, VDP22_END);
			return true;
		}
		return false;
	case VDP22_TXMIT_KA:
		vdp22st_change_state(vsi, VDP22_TXMIT_KAWAIT);
		return true;
	case VDP22_TXMIT_KAWAIT:
		if (vsi->smi.txmit_error || vsi->smi.acktimeout) {
			/* Error handover to ECP22 or no VDP22 ack */
			vdp22st_change_state(vsi, VDP22_END);
			return true;
		}
		if (vsi->smi.ackreceived) {
			vdp22st_change_state(vsi, VDP22_TXMIT_KAWAIT_2);
			return true;
		}
		return false;
	case VDP22_TXMIT_KAWAIT_2:
		if (!vsi->smi.resp_ok		/* Mismatch in response */
		    || bad_error(vsi->status)) {	/* Error without KEEP */
			vdp22st_change_state(vsi, VDP22_END);
			return true;
		}
		if (keep_error(vsi->status)
		    && vsi->resp_vsi_mode == VDP22_ASSOC)
			vdp22st_change_state(vsi, VDP22_TXMIT_DEASSOC);
		else if (vsi->resp_vsi_mode == VDP22_DEASSOC)
			vdp22st_change_state(vsi, VDP22_END);
		else
			vdp22st_change_state(vsi, VDP22_WAIT_SYSCMD);
		return true;
	case VDP22_TXMIT_DEASSOC:
		vdp22st_change_state(vsi, VDP22_TXMIT_DEAWAIT);
		return true;
	case VDP22_TXMIT_DEAWAIT:
		if (vsi->smi.txmit_error || vsi->smi.acktimeout) {
			/* Error handover to ECP22 or no VDP22 ack */
			vdp22st_change_state(vsi, VDP22_END);
			return true;
		}
		if (vsi->smi.ackreceived) {
			vdp22st_change_state(vsi, VDP22_TXMIT_DEAWAIT_2);
			return true;
		}
		return false;
	case VDP22_TXMIT_DEAWAIT_2:
		vdp22st_change_state(vsi, VDP22_END);
		return true;
	case VDP22_END:
		return false;
	}
	return false;
}

/*
 * Start state machine for VSI station
 * @vsi: pointer to currently used vsi data structure
 *
 * No return value
 */
static void vdp22st_run(struct vsi22 *vsi)
{
	vdp22st_move_state(vsi);
	do {
		LLDPAD_DBG("%s:%s state %s\n", __func__,
			   vsi->vdp->ifname, vdp22_states_n[vsi->smi.state]);

		switch (vsi->smi.state) {
		case VDP22_INIT:
			vdp22st_init(vsi);
			break;
		case VDP22_STATION_PROC:
			vdp22st_process(vsi);
			break;
		case VDP22_STATION_PROCWAIT:
		case VDP22_STATION_PROCWAIT_2:
			break;
		case VDP22_ASSOC_NEW:
		case VDP22_PREASSOC_NEW:
			vdp22st_assoc_new(vsi, vsi->resp_vsi_mode);
			vdp22_clntback(vsi);
			break;
		case VDP22_ASSOC_COMPL:
			vdp22st_assoc_compl(vsi);
			break;
		case VDP22_WAIT_SYSCMD:
			vdp22st_wait_syscmd(vsi);
			break;
		case VDP22_WAIT_SYSCMD_2:
			break;
		case VDP22_TXMIT_KA:
			vdp22st_txka(vsi);
			break;
		case VDP22_TXMIT_KAWAIT:
		case VDP22_TXMIT_KAWAIT_2:
			break;
		case VDP22_TXMIT_DEASSOC:
			vdp22st_txdea(vsi);
			break;
		case VDP22_TXMIT_DEAWAIT:
			break;
		case VDP22_TXMIT_DEAWAIT_2:
			vdp22st_assoc_compl(vsi);
			break;
		case VDP22_END:
			break;
		default:
			LLDPAD_DBG("%s:%s state %d unknown\n", __func__,
				   vsi->vdp->ifname, vsi->smi.state);
			break;
		}
	} while (vdp22st_move_state(vsi) == true);
	if (vsi->smi.state == VDP22_END)
		vdp22st_end(vsi);
}

static void vdp22_localchange_handler(UNUSED void *eloop_data, void *user_ctx)
{
	struct vsi22 *vsi;

	vsi = (struct vsi22 *) user_ctx;

	if ((vsi->smi.localchg)) {
		LLDPAD_DBG("%s:%s p->localChange %i p->ackReceived %i\n",
			   __func__, vsi->vdp->ifname, vsi->smi.localchg,
			  vsi->smi.ackreceived);
		vdp22st_run(vsi);
	}
}

int vdp22_start_localchange_timer(struct vsi22 *p)
{
	return eloop_register_timeout(0, 100, vdp22_localchange_handler, NULL,
				      (void *) p);
}

/*
 * Checks if 2 VSI records are identical.
 *
 * returns true if equal, false if not
 *
 * compares mgrid, type id, type version, id format, id and filter info format
 * returns true if they are equal.
 */
static bool vdp22_vsi_equal(struct vsi22 *p1, struct vsi22 *p2)
{
	if (memcmp(p1->mgrid, p2->mgrid, sizeof(p2->mgrid)))
		return false;
	if (p1->type_id != p2->type_id)
		return false;
	if (p1->type_ver != p2->type_ver)
		return false;
	if (p1->vsi_fmt != p2->vsi_fmt)
		return false;
	if (memcmp(p1->vsi, p2->vsi, sizeof(p1->vsi)))
		return false;
	if (p1->fif != p2->fif)
		return false;
	return true;
}

/*
 * Find a VSI in the list of VSIs already allocated
 *
 * Returns pointer to already allocated VSI in list, 0 if not.
 */
static struct vsi22 *vdp22_findvsi(struct vdp22 *vdp, struct vsi22 *me)
{
	struct vsi22 *p;

	LIST_FOREACH(p, &vdp->vsi22_que, node) {
		if (vdp22_vsi_equal(p, me))
			return p;
	}
	return NULL;
}

/*
 * Modify VSI22 information and trigger state machine.
 * Parameter me identifies the VSI to be modified.
 */
static int vdp22_modvsi(struct vsi22 *me, enum vdp22_modes x)
{
	LLDPAD_DBG("%s:%s me:%p flags:%#lx mode change %d --> %d\n", __func__,
		    me->vdp->ifname, me, me->flags, me->vsi_mode, x);
	if (me->flags & VDP22_DELETE_ME)
		return -ENODEV;
	if (me->vsi_mode > x)
		return -EINVAL;
	me->vsi_mode = x;
	me->smi.localchg = true;
	me->flags |= VDP22_BUSY | VDP22_NLCMD;
	vdp22st_run(me);
	return 0;
}

/*
 * Insert in queue and enter state machine.
 */
static void vdp22_addvsi(struct vsi22 *vsip, struct vdp22 *vdp)
{
	vsip->smi.state = VDP22_BEGIN;
	LIST_INSERT_HEAD(&vdp->vsi22_que, vsip, node);
	LLDPAD_DBG("%s:%s vsip:%p\n", __func__, vsip->vdp->ifname, vsip);
	vdp22st_run(vsip);
}

/*
 * Compare VSI filter data. Return true if they match.
 * All fields are compared, even if some are not used. Unused field are
 * initialized to zeros and always match.
 */
static bool cmp_fdata1(struct fid22 *p1, struct fid22 *p2, unsigned char fif)
{
	bool is_good = true;

	if (fif == VDP22_FFMT_MACVID || fif == VDP22_FFMT_GROUPMACVID)
		is_good = !memcmp(p1->mac, p2->mac, sizeof(p1->mac));
	if (is_good &&
		(fif == VDP22_FFMT_GROUPVID || fif == VDP22_FFMT_GROUPMACVID))
		is_good = (p1->grpid == p2->grpid);
	if (is_good) {
		if (vdp22_get_vlanid(p1->vlan))
			is_good = (vdp22_get_vlanid(p1->vlan) ==
					vdp22_get_vlanid(p2->vlan));
		if (is_good && vdp22_get_ps(p1->vlan))
			is_good = (p1->vlan == p2->vlan);
	}
	return is_good;
}

bool vdp22_cmp_fdata(struct vsi22 *p, struct vsi22 *vsip)
{
	int i;

	if (p->no_fdata != vsip->no_fdata)
		return false;
	for (i = 0; i < p->no_fdata; ++i) {
		struct fid22 *p1 = &p->fdata[i];
		struct fid22 *p2 = &vsip->fdata[i];

		if (!cmp_fdata1(p1, p2, p->fif)) {
			p->status = VDP22_RESP_NOADDR;
			return false;
		}
	}
	return true;
}

/*
 * Update a current/existing VSI instance.
 * The next table describes the transition diagram for the VSI instance update:
 *
 *		Current mode
 * New Mode   | none		preassoc	preassoc-RR	assoc
 * ===========|=================================================================
 * preassoc   | do_preassoc	do_preassoc	do_preassoc	error
 * preassoc-RR| do_preassoc-RR	do_preassoc-RR	do_preassoc-RR	error
 * assoc      | do_assoc	do_assoc	do_assoc	do-assoc
 * deassoc    | error		do_deassoc	do_deassoc	do-deassoc
 *
 * These operations get more complicated because the filter data may differ:
 * =============================================================================
 * Transitions:
 * If the filter data of the current VSI node and the new VSI node
 * matches completely, resend TLVs
 *
 * TODO:
 * If the new mode changes only part of the currently active
 * filter data, then do:
 * 1. Clone the filter data which is undergoing a mode change and
 *    create a new VSI node
 * 2. Delete the filter data in the currently active VSI node.
 * 3. Search for a VSI node with the same key and new mode:
 *    a. If such a node is found append filter data and resent TLVs
 *    b. If no such node is found, append the new VSI node with
 *       the new mode to the list of cloned VSIs. Send TLV for the
 *       new VSI node.
 *
 * If the key matches and the VSI mode is also identical and the filter data
 * in the new request does not match any filter data element in the current
 * request, then add the new filter data and resent the TLVs.
 *
 * Without the TODO items we currently support an exact match of the
 * filter data information. This is the same behavior as in the currently
 * supported IEEE 802.1 QBG draft version 0.2.
 */

/*
 * Handle a new request.
 */
int vdp22_addreq(struct vsi22 *vsip, struct vdp22 *vdp)
{
	int rc = 0;
	struct vsi22 *p;

	LLDPAD_DBG("%s:%s mode:%d\n", __func__, vsip->vdp->ifname,
		   vsip->vsi_mode);
	if (vsip->vsi_mode > VDP22_DEASSOC || vsip->vsi_mode < VDP22_PREASSOC)
		return -EINVAL;
	p = vdp22_findvsi(vdp, vsip);
	if (!p) {	/* New VSI */
		if (vsip->vsi_mode == VDP22_DEASSOC) {
			/*
			 * Disassociate of unknown VSI. Return error.
			 * Nothing to send to switch.
			 */
			rc = -EINVAL;
			LLDPAD_DBG("%s:%s dis-assoc without assoc [%02x]\n",
				   __func__, vsip->vdp->ifname, vsip->vsi[0]);
		} else
			vdp22_addvsi(vsip, vdp);	/* Add new VSI */
	} else {	/* Profile on list --> change state */
		/*
		 * Request is still busy, do not accept another one.
		 */
		if (p->flags & VDP22_BUSY) {
			rc = -EBUSY;
			goto out;
		}
		/*
		 * Check if filter data is identical. Right now support
		 * for exact filter data is implemented (as in draft 0.2)
		 *
		 * TODO
		 * Support for different filter data information.
		 */
		if (!vdp22_cmp_fdata(p, vsip)) {
			LLDPAD_DBG("%s:%s TODO mismatch filter data [%02x]\n",
				   __func__, vsip->vdp->ifname, vsip->vsi[0]);
			rc = -EINVAL;
		} else
			rc = vdp22_modvsi(p, vsip->vsi_mode);
	}
out:
	LLDPAD_DBG("%s:%s rc:%d\n", __func__, vsip->vdp->ifname, rc);
	return rc;
}

/*
 * Test for returned filter information.
 * Set VDP22_RETURN_VID bit in flags when VLAN id or QoS change is detected.
 */
static void vdp22_cpfid(struct vsi22 *hit, struct vsi22 *from)
{
	int i;
	struct fid22 *hitm = hit->fdata, *fromm = from->fdata;

	LLDPAD_DBG("%s:%s no_fdata:%hd,%hd\n", __func__, hit->vdp->ifname,
		   from->no_fdata, hit->no_fdata);
	if (hit->no_fdata != from->no_fdata)
		return;
	for (i = 0; i < hit->no_fdata; ++i, ++hitm, ++fromm) {
		LLDPAD_DBG("%s:%s vlan:%#hx,%#hx\n", __func__,
			   hit->vdp->ifname, hitm->vlan,  fromm->vlan);
		if (hitm->vlan != fromm->vlan) {
			hitm->vlan = fromm->vlan;
			hit->flags |= VDP22_RETURN_VID;
		}
	}
	LLDPAD_DBG("%s:%s flags:%#lx\n", __func__,  hit->vdp->ifname,
		   hit->flags);
}

/*
 * Input from bridge side.
 *
 * NOTE:
 * - Parameter vsip and associated fid data is on stack memory.
 */
static void vdp22_bridge_info(struct vsi22 *vsip)
{
	struct vsi22 *hit = vdp22_findvsi(vsip->vdp, vsip);

	if (!hit) {
		LLDPAD_DBG("%s:%s station received TLV not found:\n", __func__,
			   vsip->vdp->ifname);
		vdp22_showvsi(vsip);
		return;
	}
	hit->smi.ackreceived = true;
	hit->smi.deassoc = hit->smi.acktimeout = false;
	vdp22st_stop_acktimer(hit);
	hit->status = get_error(vsip->status);
	if (!(vsip->status & VDP22_ACKBIT) && vsip->vsi_mode == VDP22_DEASSOC) {
		/* Unsolicited de-assoc request from switch */
		hit->smi.deassoc = true;
		hit->status = 0;
	}
	/*
	 * We have already tested some fields of the TLV. Now test the
	 * filter data.
	 */
	if (vdp22_cmp_fdata(hit, vsip)) {
		hit->smi.resp_ok = true;
		hit->resp_vsi_mode = vsip->vsi_mode;	/* Take response */
		vdp22_cpfid(hit, vsip);			/* Take filter */
		if (hit->cc_vsi_mode != VDP22_DEASSOC
		    && (hit->resp_vsi_mode == VDP22_DEASSOC
			|| bad_error(hit->status))
		    && !(hit->flags & VDP22_NLCMD))
			hit->flags |= VDP22_NOTIFY;	/* Notify originator */
	}
	LLDPAD_DBG("%s:%s found:%p resp_ok:%d vsi_mode:%d,%d resp_vsi_mode:%d "
		   "flags:%#lx status:%#x deassoc:%d\n",
		   __func__, vsip->vdp->ifname, hit, hit->smi.resp_ok,
		   hit->vsi_mode, hit->cc_vsi_mode, hit->resp_vsi_mode,
		   hit->flags, hit->status, hit->smi.deassoc);
	vdp22st_run(hit);
}

/*
 * vdp22 input processing from ECP22 received data. Check if data is valid
 * and do some basic checks.
 */
/*
 * Advance to next packed tlv location.
 */
static inline struct vdp22_ptlv *next_ptlv(struct vdp22_ptlv *p,
					   const unsigned short len)
{
	return (struct vdp22_ptlv *)((unsigned char *)p + len);
}

/*
 * Convert a VDP22 packed TLV to vsi22 filter data.
 * Return number of bytes (in input packed TLV) processed.
 */
static size_t ptlv_2_fdata(struct fid22 *fidp, const unsigned char *cp,
			 const unsigned char ffmt)
{
	size_t offset = 0;

	memset(fidp, 0, sizeof(*fidp));
	switch (ffmt) {
	case VDP22_FFMT_VID:
		offset = extract_2o(&fidp->vlan, cp);
		break;
	case VDP22_FFMT_MACVID:
		offset = extract_no(fidp->mac, cp, sizeof(fidp->mac));
		offset += extract_2o(&fidp->vlan, cp + offset);
		break;
	case VDP22_FFMT_GROUPVID:
		offset = extract_4o(&fidp->grpid, cp);
		offset += extract_2o(&fidp->vlan, cp + offset);
		break;
	case VDP22_FFMT_GROUPMACVID:
		offset = extract_4o(&fidp->grpid, cp);
		offset += extract_no(fidp->mac, cp + offset, sizeof(fidp->mac));
		offset += extract_2o(&fidp->vlan, cp + offset);
		break;
	}
	return offset;
}

/*
 * Bridge sends replies with ACK bit set or DEASSOC request.
 * Station sends requests, ignore error bits, ACK bit must be cleared.
 */
static inline bool response_ok(struct vsi22 *vsip)
{
	if (vsip->vdp->myrole == VDP22_BRIDGE)
		return (vsip->status & VDP22_ACKBIT) ? false : true;
	if ((vsip->status & VDP22_ACKBIT) ||
	    (!(vsip->status & VDP22_ACKBIT) && vsip->vsi_mode == VDP22_DEASSOC))
		return true;
	return false;
}

/*
 * Convert a VDP22 packed TLV to vsi22 to struct vsi22 data format.
 */
static void ptlv_2_vsi22(struct vsi22 *vsip, struct vdp22_ptlv *ptlv)
{
	int i;
	size_t offset;
	unsigned char *cp = ptlv->data;

	offset = extract_1o(&vsip->status, cp);
	offset += extract_3o(&vsip->type_id, cp + offset);
	offset += extract_1o(&vsip->type_ver, cp + offset);
	offset += extract_1o(&vsip->vsi_fmt, cp + offset);
	offset += extract_no(vsip->vsi, cp + offset, sizeof(vsip->vsi));
	offset += extract_1o(&vsip->fif, cp + offset);
	offset += extract_2o(&vsip->no_fdata, cp + offset);

	if (ptlv_length(ntohs(ptlv->head)) == vsi22_ptlv_sz(vsip)
	    && vsip->no_fdata && response_ok(vsip)) {
		struct fid22 fid[vsip->no_fdata];

		vsip->fdata = fid;
		for (i = 0; i < vsip->no_fdata; ++i)
			offset += ptlv_2_fdata(&fid[i], cp + offset, vsip->fif);
		if (vsip->vdp->myrole == VDP22_STATION)
			vdp22_bridge_info(vsip);
		else
			vdp22_station_info(vsip);
		return;
	}
	LLDPAD_DBG("%s:%s TLV ignored\n", __func__, vsip->vdp->ifname);
	vdp22_showvsi(vsip);
}

/*
 * Interate along the packed TLVs and extract information. Packed TLV has
 * passed basic consistency checking.
 */
static void vdp22_input(struct vdp22 *vdp)
{
	struct vsi22 vsi;
	struct vdp22_ptlv *ptlv = (struct vdp22_ptlv *)vdp->input;
	enum vdp22_modes mode;

	LLDPAD_DBG("%s:%s input_len:%d\n", __func__, vdp->ifname,
		   vdp->input_len);
	memset(&vsi, 0, sizeof(vsi));
	vsi.vdp = vdp;
	for (; (mode = ptlv_type(ntohs(ptlv->head))) != 0;
	     ptlv = next_ptlv(ptlv, ptlv_length(ntohs(ptlv->head)))) {
		switch (mode) {
		default:
		case VDP22_ENDTLV:
			break;
		case VDP22_MGRID:
			memcpy(&vsi.mgrid, ptlv->data, sizeof(vsi.mgrid));
			break;
		case VDP22_PREASSOC:
		case VDP22_PREASSOC_WITH_RR:
		case VDP22_ASSOC:
		case VDP22_DEASSOC:
			vsi.vsi_mode = mode;
			ptlv_2_vsi22(&vsi, ptlv);
			break;
		}
	}
}

/*
 * Receive data from the ECP22 module. Check for valid input data.
 */
static void vdp22_ecp22in(UNUSED void *ctx, void *parm)
{
	struct vdp22 *vdp = (struct vdp22 *)parm;
	struct vdp22_ptlv *ptlv = (struct vdp22_ptlv *)vdp->input;
	int total_len = vdp->input_len;
	unsigned short ptlv_len;

	if (vdp->myrole == VDP22_BRIDGE && vdp->br_down) {
		LLDPAD_DBG("%s:%s bridge down\n", __func__, vdp->ifname);
		return;
	}
	/* Verify 1st TLV is a manager id TLV */
	if (ptlv_type(ntohs(ptlv->head)) != VDP22_MGRID) {
		LLDPAD_ERR("%s:%s No Manager ID TLV -- packet dropped\n",
			   __func__, vdp->ifname);
		return;
	}
	ptlv_len = ptlv_length(ntohs(ptlv->head));
	if (ptlv_len > total_len) {
		LLDPAD_ERR("%s:%s Invalid Manager ID TLV length -- "
			   "packet dropped\n", __func__, vdp->ifname);
		return;
	}
	total_len -= ptlv_len;
	do {	/* Iterrate over all packed TLVs */
		ptlv = (struct vdp22_ptlv *)((unsigned char *)ptlv + ptlv_len);
		ptlv_len = ptlv_length(ntohs(ptlv->head));

		switch (ptlv_type(ntohs(ptlv->head))) {
		case VDP22_ENDTLV:
			total_len = 0;
			break;
		case VDP22_MGRID:
			LLDPAD_ERR("%s:%s Duplicate Manager ID TLV -- "
				   "packet dropped\n", __func__, vdp->ifname);
			return;
		case VDP22_PREASSOC:
		case VDP22_PREASSOC_WITH_RR:
		case VDP22_ASSOC:
		case VDP22_DEASSOC:
			if (ptlv_len > total_len) {
				LLDPAD_ERR("%s:%s Invalid TLV length -- "
					   "packet dropped\n", __func__,
					   vdp->ifname);
				return;
			}
			total_len -= ptlv_len;
			break;
		default:
			LLDPAD_DBG("%s:%s Unknown TLV ID (%#hx) -- "
				   "ignored\n", __func__, vdp->ifname,
				   ptlv_type(ptlv->head));
			if (!ptlv_len)
				ptlv_len = 2;	/* Keep TLVs moving */
			total_len -= ptlv_len;
		}
	} while (total_len > 0);

	if (total_len < 0) {
		LLDPAD_ERR("%s:%s Received packed TLV length error (%d)\n",
			   __func__, vdp->ifname, total_len);
		return;
	}
	return vdp22_input(vdp);
}

/*
 * Called when ECP22 module delivers data. Wait a very short time to allow
 * the ECP module to return its acknowledgement before data is processed.
 */
int vdp22_from_ecp22(struct vdp22 *vdp)
{
	return eloop_register_timeout(0, 2 * 1000, vdp22_ecp22in, NULL, vdp);
}

/*
 * Bridge state machine code starts here.
 */
static void vdp22br_init(struct vsi22 *p)
{
	LLDPAD_DBG("%s:%s vsi:%p(%02x)\n", __func__, p->vdp->ifname, p,
		   p->vsi[0]);
	p->flags = 0;
	p->cc_vsi_mode = VDP22_DEASSOC;
	p->resp_vsi_mode = VDP22_RESP_NONE;
	p->smi.localchg = true;		/* Change triggered by station */
	p->smi.kato = false;
	p->smi.resp_ok = false;		/* Response from VSI manager */
	/* FOLLOWING MEMBERS NOT USED BY BRIDGE STATE MACHINE */
	p->smi.deassoc = p->smi.acktimeout = p->smi.ackreceived = false;
	p->smi.txmit = false;
	p->smi.txmit_error = 0;
}

/*
 * VSI bridge time out handler.
 */
static void vdp22br_handle_kato(UNUSED void *ctx, void *data)
{
	struct vsi22 *p = data;

	LLDPAD_DBG("%s:%s timeout keep alive timer for %#02x\n",
		   __func__, p->vdp->ifname, p->vsi[0]);
	p->smi.kato = true;
	vdp22br_run(p);
}

/*
 * Starts the VSI bridge keep alive timer.
 */
static int vdp22br_start_katimer(struct vsi22 *p)
{
	unsigned int usecs, secs;

	p->smi.kato = false;
	vdp22_timeout(p->vdp, p->vdp->vdp_rka, &secs, &usecs);
	LLDPAD_DBG("%s:%s start keep alive timer for %p(%02x) [%i,%i]\n",
		   __func__, p->vdp->ifname, p, p->vsi[0], secs, usecs);
	return eloop_register_timeout(secs, usecs, vdp22br_handle_kato, NULL,
				      (void *)p);
}

/*
 * Stops the bridge keep alive timer.
 */
static int vdp22br_stop_katimer(struct vsi22 *p)
{
	LLDPAD_DBG("%s:%s stop keep alive timer for %p(%02x)\n", __func__,
		   p->vdp->ifname, p, p->vsi[0]);
	return eloop_cancel_timeout(vdp22br_handle_kato, NULL, (void *)p);
}

/*
 * Bridge resource processing timers.
 */
static void vdp22br_handle_resto(UNUSED void *ctx, void *data)
{
	struct vsi22 *p = data;

	LLDPAD_DBG("%s:%s timeout resource wait delay for %p(%#02x)\n",
		   __func__, p->vdp->ifname, p, p->vsi[0]);
	p->smi.resp_ok = true;
	vdp22br_run(p);
}

static int vdp22br_stop_restimer(struct vsi22 *p)
{
	LLDPAD_DBG("%s:%s stop resource wait timer for %p(%02x)\n",
		   __func__, p->vdp->ifname, p, p->vsi[0]);
	return eloop_cancel_timeout(vdp22br_handle_resto, NULL, (void *)p);
}

/*
 * Start resource wait delay timer.
 */
static int vdp22br_start_restimer(struct vsi22 *p)
{
	unsigned long long towait = (1 << p->vdp->vdp_rwd) * 10;
	unsigned int secs, usecs;

	p->smi.resp_ok = false;
	p->resp_vsi_mode = VDP22_RESP_NONE;
	secs = towait / USEC_PER_SEC;
	usecs = towait % USEC_PER_SEC;
	LLDPAD_DBG("%s:%s start resource wait timer for %p(%02x) [%i,%i]\n",
		   __func__, p->vdp->ifname, p, p->vsi[0], secs, usecs);
	return eloop_register_timeout(secs, usecs, vdp22br_handle_resto, NULL,
				      (void *)p);
}

static void vdp22br_process(struct vsi22 *p)
{
	int rc, error = 0;

	LLDPAD_DBG("%s:%s vsi:%p(%02x) id:%ld\n", __func__,
		   p->vdp->ifname, p, p->vsi[0], p->type_id);
	vdp22br_start_restimer(p);
	p->status = 0;
	p->resp_vsi_mode = VDP22_RESP_SUCCESS;
	rc = vdp22br_resources(p, &error);
	switch (rc) {
	case VDP22_RESP_TIMEOUT:
		break;
	case VDP22_RESP_KEEP:
		p->status = VDP22_KEEPBIT;
		goto rest;
	case VDP22_RESP_DEASSOC:
		if (error > VDP22_STATUS_MASK)
			p->status = VDP22_HARDBIT;
		/* Fall through intended */
	case VDP22_RESP_SUCCESS:
rest:
		p->status |= VDP22_ACKBIT | make_status(error);
		vdp22br_stop_restimer(p);
		p->smi.resp_ok = true;
		break;
	}
	p->resp_vsi_mode = rc;
	LLDPAD_DBG("%s:%s resp_vsi_mode:%d status:%#x\n", __func__,
		   p->vdp->ifname, p->resp_vsi_mode, p->status);
}

void vdp22_stop_timers(struct vsi22 *vsi)
{
	vdp22st_stop_acktimer(vsi);
	vdp22st_stop_katimer(vsi);
}

static void vdp22br_end(struct vsi22 *p)
{
	LLDPAD_DBG("%s:%s vsi:%p(%02x)\n", __func__, p->vdp->ifname, p,
		   p->vsi[0]);
	vdp22_listdel_vsi(p);
}

/*
 * Add a VSI to bridge state machine.
 */
static void vdp22br_addvsi(struct vsi22 *p)
{
	LLDPAD_DBG("%s:%s vsi:%p(%02x)\n", __func__, p->vdp->ifname, p,
		   p->vsi[0]);
	p->smi.state = VDP22_BR_BEGIN;
	p->flags = VDP22_BUSY;
	LIST_INSERT_HEAD(&p->vdp->vsi22_que, p, node);
	vdp22br_run(p);
}

/*
 * Send a bridge reply. Allocate send buffer on stack and create packed TLVs.
 */
static void vdp22br_reply(struct vsi22 *vsi)
{
	unsigned short len = mgr22_ptlv_sz() + vsi22_ptlv_sz(vsi);
	unsigned char buf[len];
	struct qbg22_imm qbg;

	qbg.data_type = VDP22_TO_ECP22;
	qbg.u.c.len = len;
	qbg.u.c.data = buf;
	mgr22_2tlv(vsi, buf);
	vsi22_2tlv(vsi, buf + mgr22_ptlv_sz(), vsi->status);
	modules_notify(LLDP_MOD_ECP22, LLDP_MOD_VDP22, vsi->vdp->ifname, &qbg);
	vsi->flags &= ~VDP22_BUSY;
	vsi->smi.localchg = false;
	LLDPAD_DBG("%s:%s len:%hd rc:%d\n", __func__, vsi->vdp->ifname, len,
		   vsi->smi.txmit_error);
}

/*
 * Send a keep status TLV as bridge reply.
 */
static void vdp22br_sendack(struct vsi22 *p, unsigned char status)
{
	LLDPAD_DBG("%s:%s vsi:%p(%02x)\n", __func__, p->vdp->ifname, p,
		   p->vsi[0]);
	p->status = status;
	vdp22br_reply(p);
}

/*
 * Send a de-associate TLV as bridge reply.
 */
static void vdp22br_deassoc(struct vsi22 *p, unsigned char status)
{
	LLDPAD_DBG("%s:%s vsi:%p(%02x)\n", __func__, p->vdp->ifname, p,
		   p->vsi[0]);
	p->vsi_mode = VDP22_DEASSOC;
	vdp22br_sendack(p, status);
}

/*
 * Change bridge state machine into a new state.
 */
static void vdp22br_change_state(struct vsi22 *p, enum vdp22br_states new)
{
	switch (new) {
	case VDP22_BR_INIT:
		assert(p->smi.state == VDP22_BR_BEGIN);
		break;
	case VDP22_BR_PROCESS:
		assert(p->smi.state == VDP22_BR_WAITCMD_2
		       || p->smi.state == VDP22_BR_INIT);
		break;
	case VDP22_BR_SEND:
		assert(p->smi.state == VDP22_BR_PROCESS);
		break;
	case VDP22_BR_KEEP:
		assert(p->smi.state == VDP22_BR_PROCESS);
		break;
	case VDP22_BR_DEASSOC:
		assert(p->smi.state == VDP22_BR_PROCESS);
		break;
	case VDP22_BR_WAITCMD:
		assert(p->smi.state == VDP22_BR_SEND
		       || p->smi.state == VDP22_BR_KEEP
		       || p->smi.state == VDP22_BR_ALIVE);
		break;
	case VDP22_BR_WAITCMD_2:
		assert(p->smi.state == VDP22_BR_WAITCMD);
		break;
	case VDP22_BR_ALIVE:
		assert(p->smi.state == VDP22_BR_WAITCMD_2);
		break;
	case VDP22_BR_DEASSOCIATED:
		assert(p->smi.state == VDP22_BR_PROCESS
		       || p->smi.state == VDP22_BR_WAITCMD);
		break;
	case VDP22_BR_END:
		assert(p->smi.state == VDP22_BR_DEASSOC
		       || p->smi.state == VDP22_BR_DEASSOCIATED);
		break;
	default:
		LLDPAD_ERR("%s:%s VDP bridge machine INVALID STATE %d\n",
			   __func__, p->vdp->ifname, new);
	}
	LLDPAD_DBG("%s:%s state change %s -> %s\n", __func__,
		   p->vdp->ifname, vdp22br_state_name(p->smi.state),
		   vdp22br_state_name(new));
	p->smi.state = new;
}

/*
 * vdp22br_move_state - advances the VDP bridge state machine state
 *
 * returns true or false
 *
 * Switches the state machine to the next state depending on the input
 * variables. Returns true or false depending on wether the state machine
 * can be run again with the new state or has to stop at the current state.
 */
static bool vdp22br_move_state(struct vsi22 *p)
{
	LLDPAD_DBG("%s:%s state %s\n", __func__, p->vdp->ifname,
		   vdp22br_state_name(p->smi.state));
	switch (p->smi.state) {
	case VDP22_BR_BEGIN:
		vdp22br_change_state(p, VDP22_BR_INIT);
		return true;
	case VDP22_BR_INIT:
		vdp22br_change_state(p, VDP22_BR_PROCESS);
		return true;
	case VDP22_BR_PROCESS:
		if (!p->smi.resp_ok)	/* No resource wait response */
			return false;
		/* Assumes status and error bits set accordingly */
		if (p->resp_vsi_mode == VDP22_RESP_NONE) {	/* Timeout */
			if (p->cc_vsi_mode == VDP22_ASSOC)
				vdp22br_change_state(p, VDP22_BR_KEEP);
			else
				vdp22br_change_state(p, VDP22_BR_DEASSOCIATED);
		} else if (p->resp_vsi_mode == VDP22_RESP_SUCCESS)
			vdp22br_change_state(p, VDP22_BR_SEND);
		else if (p->resp_vsi_mode == VDP22_RESP_KEEP)
			vdp22br_change_state(p, VDP22_BR_KEEP);
		else
			vdp22br_change_state(p, VDP22_BR_DEASSOC);
		return true;
	case VDP22_BR_SEND:
	case VDP22_BR_KEEP:
		vdp22br_change_state(p, VDP22_BR_WAITCMD);
		return true;
	case VDP22_BR_DEASSOC:
		vdp22br_change_state(p, VDP22_BR_END);
		return true;
	case VDP22_BR_WAITCMD:
		if (p->smi.localchg) {		/* New station request */
			vdp22br_change_state(p, VDP22_BR_WAITCMD_2);
			return true;
		}
		if (p->smi.kato) {		/* Keep alive timeout */
			vdp22br_change_state(p, VDP22_BR_DEASSOCIATED);
			return true;
		}
		return false;
	case VDP22_BR_WAITCMD_2:		/* Handle station msg */
		if (p->cc_vsi_mode == p->vsi_mode)
			vdp22br_change_state(p, VDP22_BR_ALIVE);
		else
			vdp22br_change_state(p, VDP22_BR_PROCESS);
		return true;
	case VDP22_BR_DEASSOCIATED:
		vdp22br_change_state(p, VDP22_BR_END);
		return true;
	case VDP22_BR_ALIVE:
		vdp22br_change_state(p, VDP22_BR_WAITCMD);
		return true;
	case VDP22_BR_END:
		return false;
	default:
		LLDPAD_DBG("%s:%s unhandled state %s\n", __func__,
			    p->vdp->ifname, vdp22br_state_name(p->smi.state));
	}
	return false;
}

/*
 * Run bridge state machine.
 */
static void vdp22br_run(struct vsi22 *p)
{
	vdp22br_move_state(p);
	do {
		LLDPAD_DBG("%s:%s state %s\n", __func__,
			   p->vdp->ifname,
			   vdp22br_state_name(p->smi.state));

		switch (p->smi.state) {
		case VDP22_BR_INIT:
			vdp22br_init(p);
			break;
		case VDP22_BR_PROCESS:
			vdp22br_process(p);
			break;
		case VDP22_BR_SEND:
			vdp22br_reply(p);
			break;
		case VDP22_BR_KEEP:
			vdp22br_sendack(p, p->status);
			break;
		case VDP22_BR_DEASSOC:
			vdp22br_deassoc(p, p->status);
			break;
		case VDP22_BR_WAITCMD:
			vdp22br_start_katimer(p);
			break;
		case VDP22_BR_WAITCMD_2:
			break;
		case VDP22_BR_ALIVE:
			vdp22br_sendack(p, VDP22_ACKBIT);
			break;
		case VDP22_BR_DEASSOCIATED:
			vdp22br_deassoc(p, 0);
			break;
		case VDP22_BR_END:
			vdp22br_end(p);
			break;
		}
	} while (vdp22br_move_state(p) == true);
}

/*
 * Process the request from the station.
 *
 * NOTE:
 * - Parameter vsip and associated fid data is on stack memory.
 * - New filter information data assigned to new_fdata/new_no_fdata.
 */
static void vdp22_station_info(struct vsi22 *vsip)
{
	struct vdp22 *vdp = vsip->vdp;
	struct vsi22 *hit = vdp22_findvsi(vsip->vdp, vsip);

	LLDPAD_DBG("%s:%s received VSI hit:%p\n", __func__, vdp->ifname, hit);
	vdp22_showvsi(vsip);
	if (!hit) {
		if (vsip->vsi_mode == VDP22_DEASSOC) {
			/* Nothing allocated and de-assoc --> return ack */
			vsip->status = VDP22_ACKBIT;
		} else {
			/* Create VSI & enter init state */
			struct vsi22 *new = vdp22_copy_vsi(vsip);

			if (new)
				return vdp22br_addvsi(new);
			vsip->status = VDP22_ACKBIT
					| make_status(VDP22_RESP_NO_RESOURCES);
		}
		/* Send back response without state machine resources */
		return vdp22br_reply(vsip);
	}
	LLDPAD_DBG("%s:%s vsi_mode:%d flags:%#lx\n", __func__, vdp->ifname,
		   hit->vsi_mode, hit->flags);
	if (hit->flags & VDP22_BUSY)
		return;
	vdp22br_stop_katimer(hit);
	if (!vdp22_cmp_fdata(hit, vsip)) {
		LLDPAD_DBG("%s:%s TODO mismatch filter data [%02x]\n",
			   __func__, vsip->vdp->ifname, vsip->vsi[0]);
		return;
	}
	hit->smi.localchg = true;
	hit->vsi_mode = vsip->vsi_mode;		/* Take new request */
	vdp22br_run(hit);
}
