/******************************************************************************

  Implementation of EVB TLVs for LLDP
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <net/if.h>

#include "messages.h"
#include "config.h"

#include "lldp_qbg22.h"
#include "lldp_vdp22.h"

enum vdp22_states {
	VDP22_BEGIN = 1,
	VDP22_INIT,
	VDP22_STATION,		/* Station processing */
	VDP22_ASSOC_NEW,
	VDP22_ASSOC_COMPL,	/* Assoc complete */
	VDP22_PREASSOC_NEW,
	VDP22_WAIT_SYSCMD,
	VDP22_TXMIT_KA,		/* Transmit keep alive */
	VDP22_TXMIT_DEASSOC	/* Transmit Deassociation */
};

struct vdp22smi {		/* Data structure for VDP22 state machine */
	int state;		/* State of VDP state machine for profile */
	bool ackreceived;	/* VDP ACK received for this profile */
	bool localchg;		/* True when state needs change */
	bool remotechg;		/* True when switch caused profile change */
	bool txmit;		/* Profile transmitted */
};

static struct vdp22smi *alloc_smi(void)
{
	struct vdp22smi *smip = calloc(1, sizeof *smip);

	if (smip) {
		smip->localchg = false;
		smip->remotechg = false;
		smip->txmit = false;
		smip->ackreceived = false;
		smip->state = VDP22_BEGIN;
	}
	return smip;
}

/* vdp22_profile_equal - checks for equality of 2 profiles
 * @p1: profile 1
 * @p2: profile 2
 *
 * returns true if equal, false if not
 *
 * compares mgrid, id, version, uuid and mod of 2 vsi profiles to find
 * out if they are equal.
 */
static bool vdp22_profile_equal(struct vsi22_profile *p1,
				struct vsi22_profile *p2)
{
	if (p1->mgrid != p2->mgrid)
		return false;
	if (p1->typeid != p2->typeid)
		return false;
	if (p1->typeid_ver != p2->typeid_ver)
		return false;
	if (memcmp(p1->uuid, p2->uuid, sizeof p1->uuid))
		return false;
	return true;
}

/*
 * vdp22_findprof - Find a profile in the list of profiles already allocated
 *
 * Returns pointer to already allocated profile in list, 0 if not.
 */
static struct vsi22_profile *vdp22_findprof(struct vdp22 *vdp,
					    struct vsi22_profile *me)
{
	struct vsi22_profile *p;

	LIST_FOREACH(p, &vdp->prof22_head, prof22_node) {
		if (vdp22_profile_equal(p, me))
			return p;
	}
	return NULL;
}

/*
 * Terminate a VSI profile
 */
static void vdp22_stopprof(struct vsi22_profile *vsip)
{
	free(vsip->smi);
	vsip->smi = NULL;
	vsip->done = 1;
	LLDPAD_DBG("%s:%s profile:%p(%02x)\n", __func__, vsip->ifname, vsip,
		   vsip->uuid[PUMLAST]);
}

/*
 * Allocate VDP22 protocol state machine information and enter state machine.
 */
static int vdp22_addnew(struct vsi22_profile *vsip, struct vdp22 *vdp)
{
	int rc = -ENOMEM;

	vsip->req_response = 0;	/* TODO for testing */
	vsip->done = 0;
	vsip->smi = alloc_smi();
	if (vsip->smi) {
		LIST_INSERT_HEAD(&vdp->prof22_head, vsip, prof22_node);
		rc = 0;
	}
	LLDPAD_DBG("%s:%s rc:%d\n", __func__, vsip->ifname, rc);
	return rc;
}

/*
 * Handle a new request.
 */
int vdp22_addreq(struct vsi22_profile *vsip, struct vdp22 *vdp)
{
	int rc = 0;
	struct vsi22_profile *p;

	LLDPAD_DBG("%s:%s mode:%d\n", __func__, vsip->ifname, vsip->req_mode);
	p = vdp22_findprof(vdp, vsip);
	if (!p) {	/* New profile */
		if (vsip->req_mode == VDP22_DEASSOC) {
			/*
			 * Disassociate without any associate. Return error.
			 * Nothing to send to switch.
			 */
			rc = -EINVAL;
			LLDPAD_DBG("%s:%s dis-assoc without assoc [%02x]\n",
				   __func__, vsip->ifname, vsip->uuid[PUMLAST]);
		} else	/* Add new profile */
			rc = vdp22_addnew(vsip, vdp);
	} else {	/* Profile on list --> change state */
		if (vsip->req_mode == VDP22_DEASSOC)
			vdp22_stopprof(p);
	}
	LLDPAD_DBG("%s:%s rc:%d\n", __func__, vsip->ifname, rc);
	return rc;
}
