/******************************************************************************

  Implementation of VDP according to IEEE 802.1Qbg
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
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <linux/if_bridge.h>
#include <errno.h>
#include <assert.h>
#include "lldp.h"
#include "qbg_vdp.h"
#include "qbg_vdpnl.h"
#include "eloop.h"
#include "lldp_evb.h"
#include "messages.h"
#include "config.h"
#include "lldp_tlv.h"
#include "qbg_vdp_cmds.h"
#include "qbg_utils.h"
#include "lldp_mand_clif.h"

/* Define Module id. Must match with value in lldp_vdp_clif.c */
#define	LLDP_MOD_VDP02	((LLDP_MOD_VDP << 8) | LLDP_VDP_SUBTYPE)

static const char * const vsi_responses[] = {
	[VDP_RESPONSE_SUCCESS] = "success",
	[VDP_RESPONSE_INVALID_FORMAT] = "invalid format",
	[VDP_RESPONSE_INSUFF_RESOURCES] = "insufficient resources",
	[VDP_RESPONSE_UNUSED_VTID] = "unused VTID",
	[VDP_RESPONSE_VTID_VIOLATION] = "VTID violation",
	[VDP_RESPONSE_VTID_VER_VIOLATION] = "VTID version violation",
	[VDP_RESPONSE_OUT_OF_SYNC] = "out of sync",
	[VDP_RESPONSE_UNKNOWN] = "unknown response",
	[VDP_RESPONSE_NO_RESPONSE] = "no response",
};

const char * const vsi_states[] = {
	[VSI_UNASSOCIATED] = "VSI_UNASSOCIATED",
	[VSI_ASSOC_PROCESSING] = "VSI_ASSOC_PROCESSING",
	[VSI_ASSOCIATED] = "VSI_ASSOCIATED",
	[VSI_PREASSOC_PROCESSING] = "VSI_PREASSOC_PROCESSING",
	[VSI_PREASSOCIATED] = "VSI_PREASSOCIATED",
	[VSI_DEASSOC_PROCESSING] = "VSI_DEASSOC_PROCESSING",
	[VSI_EXIT] = "VSI_EXIT",
};

int vdp_start_localchange_timer(struct vsi_profile *p);
int vdp_remove_profile(struct vsi_profile *profile);
int vdp_trigger(struct vsi_profile *profile);

void vdp_trace_profile(struct vsi_profile *p)
{
	char instance[VDP_UUID_STRLEN + 2];
	struct mac_vlan *mac_vlan;

	vdp_uuid2str(p->instance, instance, sizeof(instance));

	LLDPAD_DBG("profile:%p mode:%d response:%d state:%d (%s) no_nlmsg:%d"
		   " txmit:%i"
		   " mgrid:%d id:%d(%#x) version:%d %s format:%d entries:%d\n",
		   p, p->mode, p->response, p->state, vsi_states[p->state],
		   p->no_nlmsg, p->txmit,
		   p->mgrid, p->id, p->id, p->version, instance, p->format,
		   p->entries);
	LIST_FOREACH(mac_vlan, &p->macvid_head, entry) {
		char macbuf[MAC_ADDR_STRLEN + 1];

		mac2str(mac_vlan->mac, macbuf, MAC_ADDR_STRLEN);
		LLDPAD_DBG("profile:%p mac:%s vlan:%d qos:%d pid:%d seq:%d\n",
			   p, macbuf, mac_vlan->vlan, mac_vlan->qos,
			   mac_vlan->req_pid, mac_vlan->req_seq);
	}
}

struct vsi_profile *vdp_alloc_profile()
{
	struct vsi_profile *prof;

	prof = calloc(1, sizeof *prof);
	if (prof)
		LIST_INIT(&prof->macvid_head);
	return prof;
}

/*
 * vdp_remove_macvlan - remove all mac/vlan pairs in the profile
 * @profile: profile to remove
 *
 * Remove all allocated <mac,vlan> pairs on the profile.
 */
static void vdp_remove_macvlan(struct vsi_profile *profile)
{
	struct mac_vlan *p;

	while ((p = LIST_FIRST(&profile->macvid_head))) {
		LIST_REMOVE(p, entry);
		free(p);
	}
}

void vdp_delete_profile(struct vsi_profile *prof)
{
	vdp_remove_macvlan(prof);
	free(prof);
}

/* vdp_profile_equal - checks for equality of 2 profiles
 * @p1: profile 1
 * @p2: profile 2
 *
 * returns true if equal, false if not
 *
 * compares mgrid, id, version, instance 2 vsi profiles to find
 * out if they are equal.
 */
static bool vdp_profile_equal(struct vsi_profile *p1, struct vsi_profile *p2)
{
	if (p1->mgrid != p2->mgrid)
		return false;

	if (p1->id != p2->id)
		return false;

	if (p1->version != p2->version)
		return false;

	if (memcmp(p1->instance, p2->instance, 16))
		return false;

	return true;
}

/*
 * vdp_find_profile - Find a profile in the list of profiles already allocated
 *
 * Returns pointer to already allocated profile in list, 0 if not.
 */

struct vsi_profile *vdp_find_profile(struct vdp_data *vd,
				     struct vsi_profile *thisone)
{
	struct vsi_profile *p;

	LIST_FOREACH(p, &vd->profile_head, profile) {
		if (vdp_profile_equal(p, thisone))
			return p;
	}
	return 0;
}

/* vdp_data - searches vdp_data in the list of modules for this port
 * @ifname: interface name to search for
 *
 * returns vdp_data on success, NULL on error
 *
 * searches the list of user_data for the VDP module user_data.
 */
struct vdp_data *vdp_data(char *ifname)
{
	struct vdp_user_data *ud;
	struct vdp_data *vd = NULL;

	ud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_VDP02);
	if (ud) {
		LIST_FOREACH(vd, &ud->head, entry) {
			if (!strncmp(ifname, vd->ifname, IFNAMSIZ))
				return vd;
		}
	}
	return NULL;
}

/* vdp_free_tlv - free tlv in vdp_data
 * @vd: vdp_data
 *
 * no return value
 *
 * frees up tlv in vdp_data. used in vdp_free_data.
 */
static void vdp_free_tlv(struct vdp_data *vd)
{
	if (vd) {
		FREE_UNPKD_TLV(vd, vdp);
	}
}

/* vdp_free_data - frees up vdp data
 * @ud: user data structure
 *
 * no return value
 *
 * removes vd_structure from the user_data list. frees up tlv in vdp_data.
 * used in vdp_unregister.
 */
static void vdp_free_data(struct vdp_user_data *ud)
{
	struct vdp_data *vd;
	if (ud) {
		while (!LIST_EMPTY(&ud->head)) {
			vd = LIST_FIRST(&ud->head);
			LIST_REMOVE(vd, entry);
			vdp_free_tlv(vd);
			free(vd);
		}
	}
}

/* vdp_response2str - map response to string
 * @response: response received
 *
 * no return value
 *
 * maps VDP response received for a profile to human readable string for
 * printing.
 */
const char *vdp_response2str(int response)
{
	if ((response >= VDP_RESPONSE_SUCCESS) &&
	    (response <= VDP_RESPONSE_OUT_OF_SYNC))
		return vsi_responses[response];

	if (response == VDP_RESPONSE_NO_RESPONSE)
		return vsi_responses[VDP_RESPONSE_NO_RESPONSE];

	return vsi_responses[VDP_RESPONSE_UNKNOWN];
}

/* vdp_ack_profiles - clear ackReceived for all profiles with seqnr
 * @vd: vd for the interface
 * @seqnr: seqnr the ack has been received with
 *
 * no return value
 *
 * clear the ackReceived for all profiles which have been sent out with
 * the seqnr that we now have received the ecp ack for.
 */
void vdp_ack_profiles(struct vdp_data *vd, int seqnr)
{
	struct vsi_profile *p;

	LIST_FOREACH(p, &vd->profile_head, profile) {
		if (p->seqnr == seqnr) {
			p->ackReceived = false;
			p->txmit = true;
		}
	}

}

/* vdp_vsis - find out number of VSIs for this interface
 * @ifname: interfac name
 *
 * returns the number of VSIs
 *
 * walk through the list of VSIs and return the count.
 */
int vdp_vsis(char *ifname)
{
	struct vdp_data *vd;
	struct vsi_profile *p;
	int count = 0;

	vd = vdp_data(ifname);

	if (!vd)
		return 0;

	LIST_FOREACH(p, &vd->profile_head, profile) {
		count++;
	}

	return count;
}

/* vdp_vsis_pending - check for pending VSIs
 * @vd: vdp data for the interface
 *
 * returns the number of VSIs found
 *
 * walk through the list of VSIs and return the count.
 */
int vdp_vsis_pending(struct vdp_data *vd)
{
	struct vsi_profile *p;
	int count = 0;

	LIST_FOREACH(p, &vd->profile_head, profile) {
		if (p->localChange && (p->txmit == false))
			count++;
	}

	return count;
}

/* vdp_somethingChangedLocal - set flag if profile has changed
 * @profile: profile to set the flag for
 * @flag: set the flag to true or false
 *
 * no return value
 *
 * set the localChange flag with a mode to indicate a profile has changed.
 * used next time when a ecpdu with profiles is sent out.
 */
void vdp_somethingChangedLocal(struct vsi_profile *profile, bool flag)
{
	LLDPAD_DBG("%s: setting profile->localChange to %s\n",
		   __func__, (flag == true) ? "true" : "false");

	profile->localChange = flag;

	if (flag == true)
		vdp_start_localchange_timer(profile);
}

/* vdp_keepaliveTimer_expired - checks for expired ack timer
 * @profile: profile to be checked
 *
 * returns true or false
 *
 * returns value of profile->keepaliveTimerExpired, true if ack timer has
 * expired, * false otherwise.
 */
static bool vdp_keepaliveTimer_expired(struct vsi_profile *profile)
{
	return (profile->keepaliveTimer == 0);
}

/* vdp_ackTimer_expired - checks for expired ack timer
 * @profile: profile to be checked
 *
 * returns true or false
 *
 * returns value of profile->ackTimerExpired, true if ack timer has expired,
 * false otherwise.
 */
static bool vdp_ackTimer_expired(struct vsi_profile *profile)
{
	return (profile->ackTimer == 0);
}

/* vdp_localchange_handler - triggers in case of vdp_ack or on vdp
 *				localchange
 * @eloop_data: data structure of event loop
 * @user_ctx: user context, vdp_data here
 *
 * no return value
 *
 * called from vdp_somethingchangedlocal or vdp_ack_profiles when a change is
 * pending. Calls the VDP station state machine. This detour is taken
 * to not having to call the vdp code from the ecp state machine. Instead, we
 * return to the event loop, giving other code a chance to do work.
 */
void vdp_localchange_handler(UNUSED void *eloop_data, void *user_ctx)
{
	struct vsi_profile *p;

	p = (struct vsi_profile *) user_ctx;

	if ((p->ackReceived) || (p->localChange)) {
		LLDPAD_DBG("%s: p->localChange %i p->ackReceived %i\n",
			   __func__, p->localChange, p->ackReceived);
		vdp_vsi_sm_station(p);
	}
}

/*
 * vdp_stop - cancel the VDP localchange timer
 *
 * returns 0 on success, -1 on error
 *
 * cancels the VPP localchange timer when a profile has been deleted.
 */
int vdp_stop_localchange_timer(struct vsi_profile *p)
{
	return eloop_cancel_timeout(vdp_localchange_handler, NULL, (void *) p);
}

/* vdp_start_localchange_timer - starts the VDP localchange timer
 * @vd: vdp_data for the interface
 *
 * returns 0 on success, -1 on error
 *
 * starts the VPP localchange timer when a localchange has been signaled from
 * the VDP state machine.
 */
int vdp_start_localchange_timer(struct vsi_profile *p)
{
	unsigned int usecs;

	usecs = VDP_LOCALCHANGE_TIMEOUT;

	return eloop_register_timeout(0, usecs, vdp_localchange_handler, NULL,
				      (void *) p);
}

/* vdp_ack_timeout_handler - handles the ack timer expiry
 * @eloop_data: data structure of event loop
 * @user_ctx: user context, vdp_data here
 *
 * no return value
 *
 * called when the VDP ack timer for a profile has expired.
 * Calls the VDP station state machine for the profile.
 */
void vdp_ack_timeout_handler(UNUSED void *eloop_data, void *user_ctx)
{
	struct vsi_profile *p = (struct vsi_profile *) user_ctx;

	if (p->ackTimer > 0)
		p->ackTimer -= VDP_ACK_TIMER_DEFAULT;

	if (vdp_ackTimer_expired(p)) {
		LLDPAD_DBG("%s: profile %#02x vdp_ackTimer_expired %i"
			   " p->ackReceived %i\n", __func__, p->instance[15],
			   vdp_ackTimer_expired(p), p->ackReceived);
		vdp_vsi_sm_station(p);
	}
}

/* vdp_start_ack_timer - starts the VDP profile ack timer
 * @profile: vsi_profile
 *
 * returns 0 on success, -1 on error
 *
 * starts the VDP profile ack timer when a profile has been handed to ecp for
 * transmission.
 */
static int vdp_start_ackTimer(struct vsi_profile *profile)
{
	unsigned int usecs;

	usecs = VDP_ACK_TIMER_DEFAULT;

	profile->ackTimer = VDP_ACK_TIMER_DEFAULT;

	LLDPAD_DBG("%s: %s starting ack timer for %#02x (%i)\n",
		   __func__, profile->port->ifname,
		   profile->instance[15], profile->ackTimer);

	return eloop_register_timeout(0, usecs, vdp_ack_timeout_handler, NULL,
				      (void *)profile);
}

/* vdp_stop_ackTimer - stops the VDP profile ack timer
 * @vd: vdp_data for the interface
 *
 * returns the number of removed handlers
 *
 * stops the VDP tck imer. Used e.g. when the host interface goes down.
 */
static int vdp_stop_ackTimer(struct vsi_profile *profile)
{
	LLDPAD_DBG("%s: %s stopping ack timer for %#02x (%i)\n", __func__,
		   profile->port->ifname, profile->instance[15],
		   profile->ackTimer);

	return eloop_cancel_timeout(vdp_ack_timeout_handler, NULL,
				    (void *)profile);
}

/* vdp_keepalive_timeout_handler - handles the keepalive timer expiry
 * @eloop_data: data structure of event loop
 * @user_ctx: user context, vdp_data here
 *
 * no return value
 *
 * called when the VDP keepalive timer for a profile has expired.
 * Calls the VDP station state machine for the profile.
 */
void vdp_keepalive_timeout_handler(UNUSED void *eloop_data, void *user_ctx)
{
	struct vsi_profile *p = (struct vsi_profile *) user_ctx;

	if (p->keepaliveTimer > 0)
		p->keepaliveTimer -= VDP_KEEPALIVE_TIMER_DEFAULT;

	if (vdp_keepaliveTimer_expired(p)) {
		LLDPAD_DBG("%s: profile %#02x vdp_keepaliveTimer_expired %i"
			   " p->ackReceived %i p->ackReceived %i\n", __func__,
			   p->instance[15], vdp_keepaliveTimer_expired(p),
			   p->ackReceived, p->ackReceived);
		vdp_vsi_sm_station(p);
	}
}

/* vdp_start_keepalive_timer - starts the VDP profile keepalive timer
 * @vd: vdp_data for the interface
 *
 * returns 0 on success, -1 on error
 *
 * starts the VDP profile keepalive timer when a profile has been handed to
 * ecp for transmission.
 */
static int vdp_start_keepaliveTimer(struct vsi_profile *profile)
{
	unsigned int usecs;

	usecs = VDP_KEEPALIVE_TIMER_DEFAULT;

	profile->keepaliveTimer = VDP_KEEPALIVE_TIMER_DEFAULT;

	LLDPAD_DBG("%s: %s starting keepalive timer for %#02x (%i)\n",
		   __func__, profile->port->ifname, profile->instance[15],
		   profile->keepaliveTimer);

	return eloop_register_timeout(0, usecs, vdp_keepalive_timeout_handler,
				      NULL, (void *) profile);
}

/* vdp_stop_keepalive_timer - stops the VDP profile keepalive timer
 * @vd: vdp_data for the interface
 *
 * returns the number of removed handlers
 *
 * stops the VDP tck imer. Used e.g. when the host interface goes down.
 */
static int vdp_stop_keepaliveTimer(struct vsi_profile *profile)
{
	profile->keepaliveTimer = VDP_KEEPALIVE_TIMER_STOPPED;

	LLDPAD_DBG("%s: %s stopping keepalive timer for %#02x (%i)\n",
		   __func__, profile->port->ifname,
		   profile->instance[15], profile->keepaliveTimer);

	return eloop_cancel_timeout(vdp_keepalive_timeout_handler, NULL,
				    (void *) profile);
}

static bool vdp_vsi_negative_response(struct vsi_profile *profile)
{
	if ((profile->response > 0) && (profile->response < 255))
		return true;
	else
		return false;
}

/* vdp_vsi_change_station_state - changes the VDP station sm state
 * @profile: profile to process
 * @newstate: new state for the sm
 *
 * no return value
 *
 * actually changes the state of the profile
 */
void vdp_vsi_change_station_state(struct vsi_profile *profile, u8 newstate)
{
	switch(newstate) {
	case VSI_UNASSOCIATED:
		break;
	case VSI_ASSOC_PROCESSING:
		assert((profile->state == VSI_PREASSOCIATED) ||
		       (profile->state == VSI_ASSOCIATED) ||
		       (profile->state == VSI_UNASSOCIATED));
		break;
	case VSI_ASSOCIATED:
		assert((profile->state == VSI_ASSOC_PROCESSING) ||
			(profile->state == VSI_ASSOCIATED));
		break;
	case VSI_PREASSOC_PROCESSING:
		assert((profile->state == VSI_PREASSOCIATED) ||
			(profile->state == VSI_ASSOCIATED) ||
			(profile->state == VSI_UNASSOCIATED));
		break;
	case VSI_PREASSOCIATED:
		assert((profile->state == VSI_PREASSOC_PROCESSING) ||
		       (profile->state == VSI_PREASSOCIATED));
		break;
	case VSI_DEASSOC_PROCESSING:
		assert((profile->state == VSI_PREASSOCIATED) ||
		       (profile->state == VSI_UNASSOCIATED) ||
		       (profile->state == VSI_ASSOCIATED));
		break;
	case VSI_EXIT:
		assert((profile->state == VSI_ASSOC_PROCESSING) ||
		       (profile->state == VSI_PREASSOC_PROCESSING) ||
		       (profile->state == VSI_DEASSOC_PROCESSING) ||
		       (profile->state == VSI_PREASSOCIATED) ||
		       (profile->state == VSI_ASSOCIATED));
		break;
	default:
		LLDPAD_ERR("ERROR: The VDP station State Machine is broken\n");
		break;
	}

	LLDPAD_DBG("%s: %s state change %s -> %s\n", __func__,
		   profile->port->ifname, vsi_states[profile->state],
		   vsi_states[newstate]);

	profile->state = newstate;
}

/* vdp_vsi_set_station_state - sets the vdp sm station state
 * @profile: profile to process
 *
 * returns true or false
 *
 * switches the state machine to the next state depending on the input
 * variables. returns true or false depending on wether the state machine
 * can be run again with the new state or can stop at the current state.
 */
static bool vdp_vsi_set_station_state(struct vsi_profile *profile)
{
	switch(profile->state) {
	case VSI_UNASSOCIATED:
		if ((profile->mode == VDP_MODE_PREASSOCIATE) ||
		    (profile->mode == VDP_MODE_PREASSOCIATE_WITH_RR)) {
			vdp_vsi_change_station_state(profile, VSI_PREASSOC_PROCESSING);
			vdp_somethingChangedLocal(profile, true);
			return true;
		} else if (profile->mode == VDP_MODE_ASSOCIATE) {
			vdp_vsi_change_station_state(profile, VSI_ASSOC_PROCESSING);
			vdp_somethingChangedLocal(profile, true);
			return true;
		} else if (profile->mode == VDP_MODE_DEASSOCIATE) {
			vdp_vsi_change_station_state(profile, VSI_DEASSOC_PROCESSING);
			vdp_somethingChangedLocal(profile, true);
			return true;
		}
		return false;
	case VSI_ASSOC_PROCESSING:
		if (profile->ackReceived) {
			if (profile->response == 0)
				vdp_vsi_change_station_state(profile, VSI_ASSOCIATED);
			else
				vdp_vsi_change_station_state(profile, VSI_EXIT);
			return true;
		} else if (!profile->ackReceived && vdp_ackTimer_expired(profile)) {
			vdp_vsi_change_station_state(profile, VSI_EXIT);
			return true;
		}
		return false;
	case VSI_ASSOCIATED:
		if (profile->mode == VDP_MODE_PREASSOCIATE) {
			vdp_vsi_change_station_state(profile, VSI_PREASSOC_PROCESSING);
			return true;
		} else if (profile->mode == VDP_MODE_DEASSOCIATE) {
			vdp_vsi_change_station_state(profile, VSI_DEASSOC_PROCESSING);
			return true;
		} else if (vdp_vsi_negative_response(profile)) {
			vdp_vsi_change_station_state(profile, VSI_EXIT);
			return true;
		} else if (vdp_keepaliveTimer_expired(profile)) {
			vdp_stop_keepaliveTimer(profile);
			vdp_somethingChangedLocal(profile, true);
			vdp_vsi_change_station_state(profile, VSI_ASSOC_PROCESSING);
			return true;
		}
		return false;
	case VSI_PREASSOC_PROCESSING:
		LLDPAD_DBG("%s: profile->ackReceived %i, vdp_ackTimer %i\n",
			   __func__, profile->ackReceived, profile->ackTimer);
		if (profile->ackReceived) {
			if (profile->response == 0)
				vdp_vsi_change_station_state(profile, VSI_PREASSOCIATED);
			else
				vdp_vsi_change_station_state(profile, VSI_EXIT);
			return true;
		} else if (!profile->ackReceived && vdp_ackTimer_expired(profile)) {
			vdp_vsi_change_station_state(profile, VSI_EXIT);
			return true;
		}
		return false;
	case VSI_PREASSOCIATED:
		if (profile->mode == VDP_MODE_ASSOCIATE) {
			vdp_vsi_change_station_state(profile, VSI_ASSOC_PROCESSING);
			return true;
		} else if (profile->mode == VDP_MODE_DEASSOCIATE) {
			vdp_vsi_change_station_state(profile, VSI_DEASSOC_PROCESSING);
			return true;
		} else if (vdp_keepaliveTimer_expired(profile)) {
			vdp_stop_keepaliveTimer(profile);
			vdp_somethingChangedLocal(profile, true);
			vdp_vsi_change_station_state(profile, VSI_PREASSOC_PROCESSING);
			return true;
		}
		return false;
	case VSI_DEASSOC_PROCESSING:
		if ((profile->ackReceived) || vdp_ackTimer_expired(profile) ||
		    profile->remoteChange) {
			vdp_vsi_change_station_state(profile, VSI_EXIT);
			return true;
		}
		return false;
	case VSI_EXIT:
		return false;
	default:
		LLDPAD_ERR("%s: VSI state machine in invalid state %d\n",
			   profile->port->ifname, profile->state);
		return false;
	}
}

/* vdp_vsi_sm_station - state machine for vdp station role
 * @profile: profile for which the state is processed
 *
 * no return value
 *
 * runs the state machine for the station role of VDP.
 */
void vdp_vsi_sm_station(struct vsi_profile *profile)
{
	struct vdp_data *vd = vdp_data(profile->port->ifname);
	int bye = 0;

	vdp_vsi_set_station_state(profile);
	do {
		LLDPAD_DBG("%s: %s station for %#02x - %s\n",
			   __func__, profile->port->ifname,
			   profile->instance[15], vsi_states[profile->state]);

		switch(profile->state) {
		case VSI_UNASSOCIATED:
			break;
		case VSI_ASSOC_PROCESSING:
			vdp_stop_keepaliveTimer(profile);
			profile->response = VDP_RESPONSE_NO_RESPONSE;
			if (profile->localChange) {
				ecp_somethingChangedLocal(vd, true);
				profile->ackReceived = false;
				vdp_start_ackTimer(profile);
			}
			break;
		case VSI_ASSOCIATED:
			profile->ackReceived = false;
			vdp_somethingChangedLocal(profile, false);
			vdp_stop_ackTimer(profile);
			vdp_start_keepaliveTimer(profile);
			break;
		case VSI_PREASSOC_PROCESSING:
			vdp_stop_keepaliveTimer(profile);
			profile->response = VDP_RESPONSE_NO_RESPONSE;
			if (profile->localChange) {
				profile->ackReceived = false;
				ecp_somethingChangedLocal(vd, true);
				vdp_start_ackTimer(profile);
			}
			break;
		case VSI_PREASSOCIATED:
			profile->ackReceived = false;
			vdp_somethingChangedLocal(profile, false);
			vdp_stop_ackTimer(profile);
			vdp_start_keepaliveTimer(profile);
			break;
		case VSI_DEASSOC_PROCESSING:
			profile->ackReceived = false;
			vdp_stop_keepaliveTimer(profile);
			profile->response = VDP_RESPONSE_NO_RESPONSE;
			if (profile->localChange) {
				profile->ackReceived = false;
				ecp_somethingChangedLocal(vd, true);
				vdp_start_ackTimer(profile);
			}
			break;
		case VSI_EXIT:
			if (profile->no_nlmsg && !profile->ackReceived &&
			    vdp_ackTimer_expired(profile))
				bye = 1;
			vdp_stop_ackTimer(profile);
			vdp_stop_keepaliveTimer(profile);
			vdp_stop_localchange_timer(profile);
			if (bye)
				vdp_remove_profile(profile);
			else
				vdp_trigger(profile);
			break;
		default:
			LLDPAD_ERR("%s: ERROR VSI state machine in invalid state %d\n",
				   vd->ifname, profile->state);
		}
	} while (vdp_vsi_set_station_state(profile) == true);

}

/* vdp_advance_sm - advance state machine after update from switch
 *
 * no return value
 */
void vdp_advance_sm(struct vdp_data *vd)
{
	struct vsi_profile *p;

	LIST_FOREACH(p, &vd->profile_head, profile) {
		LLDPAD_DBG("%s: %s station for %#02x - %s ackReceived %i\n",
			   __func__, p->port->ifname,
			   p->instance[15], vsi_states[p->state],
			   p->ackReceived);
		if (p->ackReceived) {
			vdp_vsi_sm_station(p);
			p->ackReceived = false;
		}
	}
}

/* vdp_vsi_change_bridge_state - changes the VDP bridge sm state
 * @profile: profile to process
 * @newstate: new state for the sm
 *
 * no return value
 *
 * actually changes the state of the profile
 */
static void vdp_vsi_change_bridge_state(struct vsi_profile *profile,
					u8 newstate)
{
	switch(newstate) {
	case VSI_UNASSOCIATED:
		break;
	case VSI_ASSOC_PROCESSING:
		assert((profile->state == VSI_UNASSOCIATED) ||
		      (profile->state == VSI_PREASSOCIATED) ||
		      (profile->state == VSI_ASSOCIATED));
		break;
	case VSI_ASSOCIATED:
		assert(profile->state == VSI_ASSOC_PROCESSING);
		break;
	case VSI_PREASSOC_PROCESSING:
		assert((profile->state == VSI_UNASSOCIATED) ||
		      (profile->state == VSI_PREASSOCIATED) ||
		      (profile->state == VSI_ASSOCIATED));
		break;
	case VSI_PREASSOCIATED:
		assert(profile->state == VSI_PREASSOC_PROCESSING);
		break;
	case VSI_DEASSOC_PROCESSING:
		assert((profile->state == VSI_UNASSOCIATED) ||
		      (profile->state == VSI_PREASSOCIATED) ||
		      (profile->state == VSI_ASSOCIATED));
		break;
	case VSI_EXIT:
		assert((profile->state == VSI_DEASSOC_PROCESSING) ||
		      (profile->state == VSI_PREASSOC_PROCESSING) ||
		      (profile->state == VSI_ASSOC_PROCESSING));
		break;
	default:
		LLDPAD_ERR("ERROR: The VDP bridge State Machine is broken\n");
		break;
	}
	profile->state = newstate;
}

/* vdp_vsi_set_bridge_state - sets the vdp sm bridge state
 * @profile: profile to process
 *
 * returns true or false
 *
 * switches the state machine to the next state depending on the input
 * variables. returns true or false depending on wether the state machine
 * can be run again with the new state or can stop at the current state.
 */
static bool vdp_vsi_set_bridge_state(struct vsi_profile *profile)
{
	switch(profile->state) {
	case VSI_UNASSOCIATED:
		if (profile->mode == VDP_MODE_DEASSOCIATE) {
			vdp_vsi_change_bridge_state(profile, VSI_DEASSOC_PROCESSING);
			return true;
		} else if (profile->mode == VDP_MODE_ASSOCIATE) {
			vdp_vsi_change_bridge_state(profile, VSI_ASSOC_PROCESSING);
			return true;
		} else if (profile->mode == VDP_MODE_PREASSOCIATE) {
			vdp_vsi_change_bridge_state(profile, VSI_PREASSOC_PROCESSING);
			return true;
		}
		return false;
	case VSI_ASSOC_PROCESSING:
		/* TODO: handle error case
		if (!vsiError) ||
		   (vsiError && vsiState == Assoc) {
		   */
		if (profile->mode == VDP_MODE_ASSOCIATE) {
			vdp_vsi_change_bridge_state(profile, VSI_ASSOCIATED);
			return true;
		}
		return false;
	case VSI_ASSOCIATED:
		if (profile->mode == VDP_MODE_ASSOCIATE) /* || ( INACTIVE )*/ {
			vdp_vsi_change_bridge_state(profile, VSI_DEASSOC_PROCESSING);
			return true;
		} else if (profile->mode == VDP_MODE_PREASSOCIATE) {
			vdp_vsi_change_bridge_state(profile, VSI_PREASSOC_PROCESSING);
			return true;
		}  else if (profile->mode == VDP_MODE_ASSOCIATE) {
			vdp_vsi_change_bridge_state(profile, VSI_ASSOC_PROCESSING);
			return true;
		}
		return false;
	case VSI_PREASSOC_PROCESSING:
		 if (profile->response != VDP_RESPONSE_SUCCESS) {
			vdp_vsi_change_bridge_state(profile, VSI_EXIT);
			return true;
		 }
		vdp_vsi_change_bridge_state(profile, VSI_PREASSOCIATED);
		return false;
	case VSI_PREASSOCIATED:
		if (profile->mode == VDP_MODE_ASSOCIATE) {
			vdp_vsi_change_bridge_state(profile, VSI_ASSOC_PROCESSING);
			return true;
		} else if (profile->mode == VDP_MODE_DEASSOCIATE ) {
			vdp_vsi_change_bridge_state(profile, VSI_DEASSOC_PROCESSING);
			return true;
		}  else if (profile->mode == VDP_MODE_PREASSOCIATE ) {
			vdp_vsi_change_bridge_state(profile, VSI_PREASSOC_PROCESSING);
			return true;
		}
		return false;
	case VSI_DEASSOC_PROCESSING:
		vdp_vsi_change_bridge_state(profile, VSI_EXIT);
		return false;
	case VSI_EXIT:
		return false;
	default:
		LLDPAD_ERR("%s: ERROR VSI state machine (bridge) in invalid state %d\n",
			   profile->port->ifname, profile->state);
		return false;
	}
}

/* vdp_vsi_sm_bridge - state machine for vdp bridge role
 * @profile: profile for which the state is processed
 *
 * no return value
 *
 * runs the state machine for the bridge role of VDP.
 */
static void vdp_vsi_sm_bridge(struct vsi_profile *profile)
{
	struct vdp_data *vd = vdp_data(profile->port->ifname);

	vdp_vsi_set_bridge_state(profile);
	do {
		LLDPAD_DBG("%s: %s bridge - %s\n", __func__,
		       profile->port->ifname, vsi_states[profile->state]);
		switch(profile->state) {
		case VSI_UNASSOCIATED:
			break;
		case VSI_ASSOC_PROCESSING:
			/* TODO: vsiError = ProcRxandSetCfg(remoteTLV, localtlv, vsistate);
			 *       if (vsiError)
			 *		txTLV(Assoc NACK)
			 *       else
			 *		txTLV(Assoc ACK)
			 */
			break;
		case VSI_ASSOCIATED:
			break;
		case VSI_PREASSOC_PROCESSING:
			/* TODO: vsiError = ProcRxandSetCfg(remoteTLV, localtlv, vsistate);
			 *       if (vsiError)
			 *		txTLV(PreAssoc NACK)
			 *       else
			 *		txTLV(PreAssoc ACK)
			 */
			/* for now, we always succeed */
			profile->response = VDP_RESPONSE_SUCCESS;
			ecp_rx_send_ack_frame(vd);
			break;
		case VSI_PREASSOCIATED:
			LLDPAD_DBG("%s: %s\n", __func__, profile->port->ifname);
			break;
		case VSI_DEASSOC_PROCESSING:
			/* TODO: txTLV(DeAssoc ACK) */
			break;
		case VSI_EXIT:
			vdp_remove_profile(profile);
			break;
		default:
			LLDPAD_ERR("%s: ERROR VSI state machine in invalid state %d\n",
				   vd->ifname, profile->state);
		}
	} while (vdp_vsi_set_bridge_state(profile) == true);

}

/*
 * vdp_validate_tlv - validates vsi tlvs
 * @vdp: decoded vsi tlv
 *
 * Returns 0 on success, 1 on error
 *
 * checks the contents of an already decoded vsi tlv for inconsistencies
 */
static int vdp_validate_tlv(struct tlv_info_vdp *vdp, struct unpacked_tlv *tlv)
{
	int pairs = (tlv->length - sizeof *vdp) / sizeof(struct mac_vlan_p);

	if (ntoh24(vdp->oui) != OUI_IEEE_8021Qbg) {
		LLDPAD_DBG("vdp->oui %#06x\n", ntoh24(vdp->oui));
		goto out_err;
	}

	if (vdp->sub != LLDP_VDP_SUBTYPE) {
		LLDPAD_DBG("vdp->sub %#02x\n", vdp->sub);
		goto out_err;
	}

	if (vdp->mode > VDP_MODE_DEASSOCIATE) {
		LLDPAD_DBG("unknown mode %#02x in vsi tlv\n", vdp->mode);
		goto out_err;
	}

	if (vdp->response > VDP_RESPONSE_OUT_OF_SYNC) {
		LLDPAD_DBG("unknown response %#02x\n", vdp->response);
		goto out_err;
	}

	if (vdp->format != VDP_FILTER_INFO_FORMAT_MACVID) {
		LLDPAD_DBG("unknown format %#02x in vsi tlv\n", vdp->format);
		goto out_err;
	}

	if (ntohs(vdp->entries) < 1) {
		LLDPAD_DBG("invalid # of entries %#02x in vsi tlv\n",
			    ntohs(vdp->entries));
		goto out_err;
	}

	/* Check for number of entries of MAC,VLAN pairs */
	if (ntohs(vdp->entries) != pairs) {
		LLDPAD_DBG("mismatching # of entries %#x/%#x in vsi tlv\n",
			   ntohs(vdp->entries), pairs);
		goto out_err;
	}
	return 0;

out_err:
	return 1;
}

/*
 * Create a VSI profile structure from switch response.
 */
static void make_profile(struct vsi_profile *new, struct tlv_info_vdp *vdp,
			 struct unpacked_tlv *tlv)
{
	int i;
	u8 *pos = tlv->info + sizeof *vdp;

	new->mode = vdp->mode;
	new->response = vdp->response;
	new->mgrid = vdp->mgrid;
	new->id = ntoh24(vdp->id);
	new->version = vdp->version;
	memcpy(&new->instance, &vdp->instance, sizeof new->instance);
	new->format = vdp->format;
	new->entries = ntohs(vdp->entries);
	LLDPAD_DBG("%s: MAC/VLAN filter info format %u, # of entries %u\n",
		   __func__, new->format, new->entries);

	/* Add MAC,VLAN to list */
	for (i = 0; i < new->entries; ++i) {
		struct mac_vlan *mac_vlan = calloc(1, sizeof(struct mac_vlan));
		u16 vlan;
		char macbuf[MAC_ADDR_STRLEN + 1];

		if (!mac_vlan) {
			new->entries = i;
			return;
		}
		memcpy(&mac_vlan->mac, pos, ETH_ALEN);
		pos += ETH_ALEN;
		mac2str(mac_vlan->mac, macbuf, MAC_ADDR_STRLEN);
		memcpy(&vlan, pos, 2);
		pos += 2;
		mac_vlan->vlan = ntohs(vlan);
		LLDPAD_DBG("%s: mac %s vlan %d\n", __func__, macbuf,
			   mac_vlan->vlan);
		LIST_INSERT_HEAD(&new->macvid_head, mac_vlan, entry);
	}
}

/*
 * vdp_indicate - receive VSI TLVs from ECP
 * @port: the port on which the tlv was received
 * @tlv: the unpacked tlv to receive
 *
 * Returns 0 on success
 *
 * receives a vsi tlv and creates a profile. Take appropriate action
 * depending on the role of the (receive) port
 */
int vdp_indicate(struct vdp_data *vd, struct unpacked_tlv *tlv)
{
	struct tlv_info_vdp vdp;
	struct vsi_profile *p, *profile;
	struct port *port = port_find_by_ifindex(get_ifidx(vd->ifname));

	LLDPAD_DBG("%s: indicating vdp of length %u (%zu) for %s\n",
		   __func__, tlv->length, sizeof(struct tlv_info_vdp),
		   vd->ifname);

	if (!port) {
		LLDPAD_ERR("%s: port not found for %s\n", __func__,
			   vd->ifname);
		goto out_err;
	}

	memset(&vdp, 0, sizeof vdp);
	/* copy only vdp header w/o list of mac/vlan/groupid pairs */
	memcpy(&vdp, tlv->info, sizeof vdp);

	if (vdp_validate_tlv(&vdp, tlv)) {
		LLDPAD_ERR("%s: invalid TLV received\n", __func__);
		goto out_err;
	}

	profile = vdp_alloc_profile();
	if (!profile) {
		LLDPAD_ERR("%s: unable to allocate profile\n", __func__);
		goto out_err;
	}
	make_profile(profile, &vdp, tlv);

	profile->port = port;

	if (vd->role == VDP_ROLE_STATION) {
		/* do we have the profile already ? */
		p = vdp_find_profile(vd, profile);
		if (p) {
			LLDPAD_DBG("%s: station profile found localChange %i "
				   "ackReceived %i no_nlmsg:%d\n",
				   __func__, p->localChange, p->ackReceived,
				   p->no_nlmsg);

			if (profile->mode == VDP_MODE_DEASSOCIATE &&
			    (p->response == VDP_RESPONSE_NO_RESPONSE ||
			     p->response == VDP_RESPONSE_SUCCESS) &&
			    p->mode == VDP_MODE_PREASSOCIATE) {
				LLDPAD_DBG("%s: ignore dis-associate request "
					   "in pre-association\n", __func__);
				vdp_delete_profile(profile);
				return 0;
			}

			p->ackReceived = true;
			p->keepaliveTimer = VDP_KEEPALIVE_TIMER_DEFAULT;
			if (profile->mode != p->mode) {
				p->mode = profile->mode;
				p->remoteChange = true;
				if (profile->mode == VDP_MODE_DEASSOCIATE)
					p->no_nlmsg = 0;
			} else
				p->remoteChange = false;
			p->response = profile->response;
			LLDPAD_DBG("%s: remoteChange %i no_nlmsg %d mode %d\n",
				   __func__, p->remoteChange, p->no_nlmsg,
				   p->mode);
			if (vdp_vsi_negative_response(p))
				p->mode = VDP_MODE_DEASSOCIATE;

			LLDPAD_DBG("%s: profile response: %s (%i) "
				   "for profile %#02x at state %s\n",
				   __func__,
				   vdp_response2str(p->response),
				   p->response, p->instance[15],
				   vsi_states[p->state]);
		} else {
			LLDPAD_DBG("%s: station profile not found\n", __func__);
		}
		vdp_delete_profile(profile);
	}

	if (vd->role == VDP_ROLE_BRIDGE) {
		/* do we have the profile already ? */
		p = vdp_find_profile(vd, profile);
		if (p) {
			LLDPAD_DBG("%s: bridge profile found\n", __func__);
			vdp_delete_profile(profile);
		} else {
			LLDPAD_DBG("%s: bridge profile not found\n", __func__);
			/* put it in the list  */
			profile->state = VSI_UNASSOCIATED;
			LIST_INSERT_HEAD(&vd->profile_head, profile, profile);
		}

		vdp_vsi_sm_bridge(profile);
	}

	return 0;

out_err:
	return 1;
}

/*
 * vdp_bld_vsi_tlv - build the VDP VSI TLV
 * @vd: vdp_data structure for this port
 * @profile: profile the vsi tlv is created from
 *
 * Returns 0 on success, ENOMEM otherwise
 *
 * creates a vdp structure from an existing profile
 */
static int vdp_bld_vsi_tlv(struct vdp_data *vd, struct vsi_profile *profile)
{
	struct mac_vlan *mv;
	struct mac_vlan_p *mv_p;
	struct tlv_info_vdp *vdp;
	int rc = 0;
	struct unpacked_tlv *tlv = NULL;
	int size = sizeof(struct tlv_info_vdp) +
		profile->entries * sizeof(struct mac_vlan_p);

	vdp = malloc(size);

	if (!vdp) {
		LLDPAD_DBG("%s: unable to allocate memory for VDP TLV\n",
			   __func__);
		rc = ENOMEM;
		goto out_err;
	}

	memset(vdp, 0, size);

	hton24(vdp->oui, OUI_IEEE_8021Qbg);
	vdp->sub = LLDP_VDP_SUBTYPE;
	vdp->mode = profile->mode;
	vdp->response = 0;
	vdp->mgrid = profile->mgrid;
	hton24(vdp->id, profile->id);
	vdp->version = profile->version;
	memcpy(&vdp->instance, &profile->instance, 16);
	vdp->format = VDP_FILTER_INFO_FORMAT_MACVID;
	vdp->entries = htons(profile->entries);

	mv_p = (struct mac_vlan_p *)(vdp + 1);

	LIST_FOREACH(mv, &profile->macvid_head, entry) {
		memcpy(mv_p->mac, mv->mac, MAC_ADDR_LEN);
		mv_p->vlan = htons(mv->vlan);
		mv_p++;
	}

	tlv = create_tlv();
	if (!tlv) {
		rc = ENOMEM;
		goto out_free;
	}

	tlv->type = ORG_SPECIFIC_TLV;
	tlv->length = size;
	tlv->info = (u8 *)malloc(tlv->length);
	if(!tlv->info) {
		free(tlv);
		tlv = NULL;
		rc = ENOMEM;
		goto out_free;
	}

	FREE_UNPKD_TLV(vd, vdp);

	memcpy(tlv->info, vdp, tlv->length);

	vd->vdp = tlv;

out_free:
	free(vdp);

out_err:
	return rc;
}

/* vdp_bld_tlv - builds a tlv from a profile
 * @vd: vdp_data structure for this port
 * @profile: profile the vsi tlv is created from
 *
 * returns 0 on success, != 0 on error
 *
 * wrapper function around vdp_bld_vsi_tlv. adds some checks and calls
 * vdp_bld_vsi_tlv.
 */

static int vdp_bld_tlv(struct vdp_data *vd, struct vsi_profile *profile)
{
	if (!port_find_by_ifindex(get_ifidx(vd->ifname)))
		return -EEXIST;

	if (vdp_bld_vsi_tlv(vd, profile)) {
		LLDPAD_ERR("%s: %s vdp_bld_vsi_tlv() failed\n",
				__func__, vd->ifname);
		return -EINVAL;
	}

	return 0;
}

/* vdp_gettlv - get the tlv for a profile
 * @port: the port on which the tlv was received
 * @profile: profile the vsi tlv is created from
 *
 * returns 0 on success
 *
 * this is the interface function called from ecp_build_ECPDU. It returns the
 * packed tlv for a profile.
 */
struct packed_tlv *vdp_gettlv(struct vdp_data *vd, struct vsi_profile *profile)
{
	int size;
	struct packed_tlv *ptlv = NULL;

	/* frees the unpacked_tlv in vdp_data
	 * also done in vdp_bld_vsi_tlv */
	vdp_free_tlv(vd);

	if (vdp_bld_tlv(vd, profile)) {
		LLDPAD_ERR("%s: %s vdp_bld_tlv failed\n",
			__func__, vd->ifname);
		goto out_err;
	}

	size = TLVSIZE(vd->vdp);

	if (!size) {
		LLDPAD_ERR("%s: size %i of unpacked_tlv not correct\n",
			   __func__, size);
		goto out_err;
	}

	ptlv = create_ptlv();
	if (!ptlv)
		goto out_err;

	ptlv->tlv = malloc(size);
	if (!ptlv->tlv)
		goto out_free;

	ptlv->size = 0;
	PACK_TLV_AFTER(vd->vdp, ptlv, size, out_free);

	return ptlv;

out_free:
	ptlv = free_pkd_tlv(ptlv);
out_err:
	LLDPAD_ERR("%s: %s failed\n", __func__, vd->ifname);
	return NULL;
}

/* vdp_macvlan_equal - checks for equality of 2 mac/vlan pairs
 * @mv1: mac/vlan pair 1
 * @mv2: mac/vlan pair 2
 *
 * returns true if equal, false if not
 *
 * compares mac address and vlan if they are equal.
 */
bool vdp_macvlan_equal(struct mac_vlan *mv1, struct mac_vlan *mv2)
{
	if (memcmp(mv1->mac, mv2->mac, MAC_ADDR_LEN))
		return false;

	if (mv1->vlan != mv2->vlan)
		return false;

	return true;
}

/*
 * Check if the current profile already has this entry. If so take over
 * PID and other fields. If not add this MAC,VLAN to our list.
 *
 * Returns 1 it the entry already exist, 0 if not.
 */
static int have_macvlan(struct vsi_profile *p1, struct mac_vlan *new)
{
	struct mac_vlan *mv1;

	LIST_FOREACH(mv1, &p1->macvid_head, entry)
		if (vdp_macvlan_equal(mv1, new) == true) {
			mv1->req_pid = new->req_pid;
			mv1->req_seq = new->req_seq;
			mv1->qos = new->qos;
			return 1;
		}
	LIST_INSERT_HEAD(&p1->macvid_head, new, entry);
	p1->entries++;
	return 0;
}

/* vdp_takeover_macvlans - take over macvlan pairs from p2 into p1
 * @p1: profile 1
 * @p2: profile 2
 *
 * returns number of mac/vlan pairs taken over
 *
 * loops over all mac/vlan pairs in profile 2 and looks for them in profile 1.
 * If the mac/vlan pair does not yet exist in profile 1, it adds the new pair to
 * the list in profile 1.
 */
void vdp_takeover_macvlans(struct vsi_profile *p1, struct vsi_profile *p2)
{
	struct mac_vlan *mv2;
	int count = 0;

	LLDPAD_DBG("%s: taking over mac/vlan pairs\n", __func__);

	while ((mv2 = LIST_FIRST(&p2->macvid_head))) {
		LIST_REMOVE(mv2, entry);
		p2->entries--;
		if (have_macvlan(p1, mv2))
			free(mv2);
		else
			count++;
	}

	LLDPAD_DBG("%s: %u mac/vlan pairs taken over\n", __func__, count);
}

/* vdp_add_profile - adds a profile to a per port list
 * @profile: profile to add
 *
 * returns the profile that has been found or added, NULL otherwise.
 *
 * main interface function which adds a profile to a list kept on a per-port
 * basis. Checks if the profile is already in the list, adds it if necessary.
 */
struct vsi_profile *vdp_add_profile(struct vdp_data *vd,
				    struct vsi_profile *profile)
{
	struct vsi_profile *p;

	LLDPAD_DBG("%s: adding vdp profile for %s\n", __func__,
		   profile->port->ifname);
	vdp_trace_profile(profile);

	/*
	 * Search this profile. If found check,
	 * if the MAC/VLAN pair already exists. If not, add it.
	 */
	p = vdp_find_profile(vd, profile);
	if (p) {
		LLDPAD_DBG("%s: profile already exists\n", __func__);

		vdp_takeover_macvlans(p, profile);

		if (p->mode != profile->mode) {
			LLDPAD_DBG("%s: new mode %i\n",
				   __func__, profile->mode);
			p->mode = profile->mode;
			p->response = VDP_RESPONSE_NO_RESPONSE;
		}
		profile = p;
	} else {

		/*
		 * Libvirt sends dis-assoc command and no profile active.
		 * Add to list with successful status to return the success
		 * to libvirtd when it queries for results.
		 */
		if (profile->mode == VDP_MODE_DEASSOCIATE) {
			profile->response = VDP_RESPONSE_SUCCESS;
			LLDPAD_DBG("%s: dis-assoc without profile\n", __func__);
		} else
			profile->response = VDP_RESPONSE_NO_RESPONSE;

		LIST_INSERT_HEAD(&vd->profile_head, profile, profile);
	}

	if (profile->response != VDP_RESPONSE_SUCCESS)
		vdp_somethingChangedLocal(profile, true);

	return profile;
}

/* vdp_remove_profile - remove a profile from a per port list
 * @profile: profile to remove
 *
 * returns 0 if removal was successful, -1 if removal failed
 *
 * function used in the state machines to remove a profile from a list kept on
 * a per-port basis. Checks if the profile is in the list, removes it if there.
 */
int vdp_remove_profile(struct vsi_profile *profile)
{
	struct vsi_profile *p;
	struct vdp_data *vd;

	LLDPAD_DBG("%s: removing vdp profile on %s\n", __func__,
		   profile->port->ifname);
	vdp_trace_profile(profile);

	vd = vdp_data(profile->port->ifname);
	if (!vd) {
		LLDPAD_ERR("%s: could not find vdp_data for %s\n", __func__,
			   profile->port->ifname);
		return -1;
	}
	/* Check if profile exists. If yes, remove it. */
	p = vdp_find_profile(vd, profile);
	if (p) {
		LIST_REMOVE(p, profile);
		vdp_delete_profile(p);
		return 0;
	}
	return -1;	/* Not found */
}

/* vdp_ifdown - tear down vdp structures for a interface
 * @ifname: name of the interface
 *
 * no return value
 *
 * interface function to lldpad. tears down vdp specific structures if
 * interface "ifname" goes down.
 */
void vdp_ifdown(char *ifname, UNUSED struct lldp_agent *agent)
{
	struct vdp_data *vd;
	struct vsi_profile *p;

	LLDPAD_DBG("%s: called on interface %s\n", __func__, ifname);

	vd = vdp_data(ifname);
	if (!vd)
		goto out_err;

	if (ecp_deinit(ifname))
		goto out_err;

	LIST_FOREACH(p, &vd->profile_head, profile) {
		if (p->ackTimer > 0)
			vdp_stop_ackTimer(p);
		if (p->keepaliveTimer > 0)
			vdp_stop_keepaliveTimer(p);
	}

	LLDPAD_INFO("%s: %s vdp data removed\n", __func__, ifname);
	return;
out_err:
	LLDPAD_INFO("%s: %s vdp data remove failed\n", __func__, ifname);

	return;
}

/* vdp_ifup - build up vdp structures for a interface
 * @ifname: name of the interface
 *
 * no return value
 *
 * interface function to lldpad. builds up vdp specific structures if
 * interface "ifname" goes up.
 */
void vdp_ifup(char *ifname, struct lldp_agent *agent)
{
	char *role;
	char config_path[16];
	struct vdp_data *vd;
	struct vdp_user_data *ud;
	struct vsi_profile *p;
	int enabletx = false;

	LLDPAD_DBG("%s: %s agent:%d start VDP\n",
		   __func__, ifname, agent->type);

	snprintf(config_path, sizeof(config_path), "%s.%s",
		 VDP_PREFIX, ARG_TLVTXENABLE);

	if (get_config_setting(ifname, agent->type, config_path,
			       (void *)&enabletx, CONFIG_TYPE_BOOL))
			enabletx = false;

	if (enabletx == false) {
		LLDPAD_DBG("%s: %s not enabled for VDP\n", __func__, ifname);
		return;
	}

	vd = vdp_data(ifname);
	if (vd) {
		vd->enabletx = enabletx;

		LLDPAD_WARN("%s: %s vdp data already exists\n",
			    __func__, ifname);
		goto out_start_again;
	}

	/* not found, alloc/init per-port module data */
	vd = (struct vdp_data *) calloc(1, sizeof(struct vdp_data));
	if (!vd) {
		LLDPAD_ERR("%s: %s malloc %zu failed\n",
			 __func__, ifname, sizeof(*vd));
		goto out_err;
	}
	STRNCPY_TERMINATED(vd->ifname, ifname, IFNAMSIZ);

	vd->role = VDP_ROLE_STATION;
	vd->enabletx = enabletx;

	if (!get_cfg(ifname, NEAREST_CUSTOMER_BRIDGE, "vdp.role", (void *)&role,
		    CONFIG_TYPE_STRING)) {
		if (!strcasecmp(role, VAL_BRIDGE)) {
			vd->role = VDP_ROLE_BRIDGE;
		}
	}

	LLDPAD_DBG("%s: configured for %s mode\n", ifname,
	       (vd->role ==VDP_ROLE_BRIDGE) ? "bridge" : "station");

	LIST_INIT(&vd->profile_head);

	ud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_VDP02);
	LIST_INSERT_HEAD(&ud->head, vd, entry);

out_start_again:
	if (ecp_init(ifname)) {
		LLDPAD_ERR("%s: %s unable to init ecp\n", __func__, ifname);
		vdp_ifdown(ifname, agent);
		goto out_err;
	}

	vd->keepaliveTimer = VDP_KEEPALIVE_TIMER_DEFAULT;
	vd->ackTimer = VDP_ACK_TIMER_DEFAULT;

	LLDPAD_DBG("%s: %s starting vdp timer (%i)\n", __func__,
		   vd->ifname, vd->nroftimers);

	LIST_FOREACH(p, &vd->profile_head, profile) {
		if (p->ackTimer > 0) {
			vdp_somethingChangedLocal(p, true);
			vdp_start_ackTimer(p);
		}
		if (p->keepaliveTimer > 0)
			vdp_start_keepaliveTimer(p);
	}

	LLDPAD_DBG("%s: %s agent:%d vdp added\n", __func__, ifname,
		   agent->type);
	return;

out_err:
	LLDPAD_ERR("%s: %s agent:%d vdp adding failed\n",
		   __func__, ifname, agent->type);
}

static int vdp_client_cmd(UNUSED void *data, UNUSED struct sockaddr_un *from,
		   UNUSED socklen_t fromlen, char *ibuf, int ilen,
		   char *rbuf, int rlen)
{
	return vdp_clif_cmd(ibuf, ilen, rbuf, rlen);
}

static const struct lldp_mod_ops vdp_ops =  {
	.lldp_mod_register	= vdp_register,
	.lldp_mod_unregister	= vdp_unregister,
	.get_arg_handler	= vdp_get_arg_handlers,
	.client_cmd             = vdp_client_cmd
};

/* vdp_register - register vdp module to lldpad
 * @none
 *
 * returns lldp_module struct on success, NULL on error
 *
 * allocates a module structure with vdp module information and returns it
 * to lldpad.
 */
struct lldp_module *vdp_register(void)
{
	struct lldp_module *mod;
	struct vdp_user_data *ud;

	mod = malloc(sizeof(*mod));
	if (!mod) {
		LLDPAD_ERR("%s: failed to start - vdp data\n", __func__);
		return NULL;
	}
	ud = malloc(sizeof(struct vdp_user_data));
	if (!ud) {
		free(mod);
		LLDPAD_ERR("%s: failed to start - vdp user data\n", __func__);
		return NULL;
	}
	LIST_INIT(&ud->head);
	mod->id = LLDP_MOD_VDP02;
	mod->ops = &vdp_ops;
	mod->data = ud;
	LLDPAD_DBG("%s: done\n", __func__);
	return mod;
}

/* vdp_unregister - unregister vdp module from lldpad
 * @none
 *
 * no return value
 *
 * frees vdp module structure.
 */
void vdp_unregister(struct lldp_module *mod)
{
	if (mod->data) {
		vdp_free_data((struct vdp_user_data *) mod->data);
		free(mod->data);
	}
	free(mod);
	LLDPAD_DBG("%s: done\n", __func__);
}

void vdp_update(char *ifname, u8 ccap)
{
	struct vdp_data *vdp = vdp_data(ifname);

	if (vdp) {
		vdp->vdpbit_on = ccap & LLDP_EVB_CAPABILITY_PROTOCOL_VDP;
		LLDPAD_DBG("%s:%s vdpbit_on %d\n", __func__, ifname,
			   vdp->vdpbit_on);
	}
}

/*
 * Handle a VSI request from buddy.
 */
int vdp_request(struct vdpnl_vsi *vsi)
{
	struct vdp_data *vd;
	struct vsi_profile *profile, *p;
	struct port *port = port_find_by_ifindex(get_ifidx(vsi->ifname));
	struct mac_vlan *mac_vlan;
	int ret = 0;

	vd = vdp_data(vsi->ifname);
	if (!vd) {
		LLDPAD_ERR("%s: %s has not yet been configured\n", __func__,
			   vsi->ifname);
		return -ENXIO;
	}
	if (!vd->vdpbit_on) {
		LLDPAD_ERR("%s: %s has VDP disabled\n", __func__, vsi->ifname);
		return -ENXIO;
	}

	if (!port) {
		LLDPAD_ERR("%s: %s can not find port\n", __func__, vsi->ifname);
		return -ENODEV;
	}
	/* If the link is down, reject request */
	if (!port->portEnabled && vsi->request != VDP_MODE_DEASSOCIATE) {
		LLDPAD_WARN("%s: %s not enabled, unable to associate\n",
			    __func__, vsi->ifname);
		return -ENXIO;
	}

	profile = vdp_alloc_profile();
	if (!profile)
		return -ENOMEM;
	mac_vlan = calloc(1, sizeof(struct mac_vlan));
	if (!mac_vlan) {
		ret = -ENOMEM;
		goto out_err;
	}

	profile->port = port;
	memcpy(&mac_vlan->mac, vsi->maclist->mac, sizeof mac_vlan->mac);
	mac_vlan->vlan = vsi->maclist->vlan;
	mac_vlan->qos = vsi->maclist->qos;
	mac_vlan->req_pid = vsi->req_pid;
	mac_vlan->req_seq = vsi->req_seq;
	LIST_INSERT_HEAD(&profile->macvid_head, mac_vlan, entry);
	profile->entries = 1;

	profile->mgrid = vsi->vsi_mgrid;
	profile->id = vsi->vsi_typeid;
	profile->version = vsi->vsi_typeversion;
	profile->mode = vsi->request;
	profile->response = vsi->response;
	memcpy(profile->instance, vsi->vsi_uuid, sizeof vsi->vsi_uuid);
	p = vdp_add_profile(vd, profile);
	p->no_nlmsg = 1;
	p->txmit = false;
	vdp_trace_profile(p);
	if (p != profile)
		goto out_err;
	return ret;

out_err:
	vdp_delete_profile(profile);
	return ret;
}

/*
 * Query a VSI request from buddy and report its progress. Use the interface
 * name to determine the VSI profile list. Return one entry in parameter 'vsi'
 * use the structure members response and vsi_uuid.
 * Returns
 * 1  valid VSI data returned
 * 0  end of queue (no VSI data returned)
 * <0 errno
 */
int vdp_status(int number, struct vdpnl_vsi *vsi)
{
	struct vdp_data *vd;
	struct vsi_profile *p;
	int i = 0, ret = 0;

	vd = vdp_data(vsi->ifname);
	if (!vd) {
		LLDPAD_ERR("%s: %s has not yet been configured\n", __func__,
			   vsi->ifname);
		return -ENODEV;
	}
	/* Interate to queue element number */
	LIST_FOREACH(p, &vd->profile_head, profile) {
		if (++i == number) {
			ret = 1;
			break;
		}
	}
	if (ret) {
		vdp_trace_profile(p);
		vsi->macsz = 0;
		vsi->response = p->response;
		memcpy(vsi->vsi_uuid, p->instance, sizeof vsi->vsi_uuid);
		if (p->response != VDP_RESPONSE_NO_RESPONSE
		    && p->state == VSI_EXIT)
			vdp_remove_profile(p);
	}
	LLDPAD_DBG("%s: entry:%d more:%d\n", __func__, number, ret);
	return ret;
}

/*
 * Copy MAC-VLAN list from profile to vdpnl structure.
 */
static void copy_maclist(struct vsi_profile *p, struct vdpnl_mac *macp)
{
	struct mac_vlan *mv1;

	LIST_FOREACH(mv1, &p->macvid_head, entry) {
		macp->vlan = mv1->vlan;
		macp->qos =  mv1->qos;
		memcpy(macp->mac, mv1->mac, sizeof macp->mac);
		++macp;
	}
}

/*
 * Prepare data for a netlink message to originator of VSI.
 * Forward a notification from switch.
 */
int vdp_trigger(struct vsi_profile *profile)
{
	struct vdpnl_vsi vsi;
	struct vdp_data *vd;
	struct mac_vlan *macp = 0;
	int rc = -EINVAL;
	struct vdpnl_mac maclist[profile->entries];

	vsi.macsz = profile->entries;
	vsi.maclist = maclist;
	LLDPAD_DBG("%s: no_nlmsg:%d\n", __func__, profile->no_nlmsg);
	vdp_trace_profile(profile);
	if (profile->no_nlmsg)
		return 0;
	if (LIST_EMPTY(&profile->macvid_head))
		return 0;
	macp = LIST_FIRST(&profile->macvid_head);
	if (!macp->req_pid)
		return 0;
	sleep(1);		/* Delay message notification */
	if (!profile->port || !profile->port->ifname[0]) {
		LLDPAD_ERR("%s: no ifname found for profile %p:\n", __func__,
			   profile);
		goto error_exit;
	}
	memcpy(vsi.ifname, profile->port->ifname, sizeof vsi.ifname);
	vd = vdp_data(vsi.ifname);
	if (!vd) {
		LLDPAD_ERR("%s: %s could not find vdp_data\n", __func__,
			   vsi.ifname);
		goto error_exit;
	}
	vsi.ifindex = if_nametoindex(vsi.ifname);
	if (vsi.ifindex == 0) {
		LLDPAD_ERR("%s: %s could not find index for ifname\n",
			   __func__, vsi.ifname);
		goto error_exit;
	}
	vsi.macsz = profile->entries;
	copy_maclist(profile, vsi.maclist);
	vsi.req_pid = macp->req_pid;
	vsi.req_seq = macp->req_seq;
	vsi.vsi_mgrid = profile->mgrid;
	vsi.vsi_typeid = profile->id;
	vsi.vsi_typeversion = profile->version;
	memcpy(vsi.vsi_uuid, profile->instance, sizeof vsi.vsi_uuid);
	vsi.request = VDP_MODE_DEASSOCIATE;
	rc = vdpnl_send(&vsi);
error_exit:
	vdp_remove_profile(profile);
	return rc;
}
