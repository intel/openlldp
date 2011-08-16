/*******************************************************************************

  implementation of VDP according to IEEE 802.1Qbg
  (c) Copyright IBM Corp. 2010

  Author(s): Jens Osterkamp <jens at linux.vnet.ibm.com>

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

*******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <linux/if_bridge.h>
#include <errno.h>
#include <assert.h>
#include "lldp.h"
#include "lldp_vdp.h"
#include "ecp/ecp.h"
#include "eloop.h"
#include "lldp_evb.h"
#include "messages.h"
#include "config.h"
#include "lldp_tlv.h"
#include "lldp_vdp_cmds.h"

const char * const vsi_responses[] = {
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
int vdp_profile_equal(struct vsi_profile *p1, struct vsi_profile *p2);

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

	ud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_VDP);
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

/* vdp_print_profile - print a vsi profile
 * @profile: profile to print
 *
 * no return value
 *
 * prints the contents of a profile first to a string using the PRINT_PROFILE
 * macro, and then to the screen. Used for debug purposes.
 */
void vdp_print_profile(struct vsi_profile *profile)
{
	LLDPAD_DBG("profile:\n");

	LLDPAD_DBG("mode: %i\n", profile->mode);
	LLDPAD_DBG("response: %i\n", profile->response);
	LLDPAD_DBG("state: %i\n", profile->state);
	LLDPAD_DBG("mgrid: %i\n", profile->mgrid);
	LLDPAD_DBG("id: %x\n", profile->id);
	LLDPAD_DBG("version: %i\n", profile->version);

	char macbuf[MAC_ADDR_STRLEN+1];
	char instance[INSTANCE_STRLEN+2];
	instance2str(profile->instance, instance, sizeof(instance));
	LLDPAD_DBG("instance: %s\n", &instance[0]);
	mac2str(profile->mac, macbuf, MAC_ADDR_STRLEN);
	LLDPAD_DBG("mac: %s\n", macbuf);

	LLDPAD_DBG("vlan: %i\n", profile->vlan);
}

/* vdp_ack_profiles - set ackReceived for all profiles with seqnr
 * @vd: vd for the interface
 * @seqnr: seqnr the ack has been received with
 *
 * no return value
 *
 * set the ackReceived for all profiles which have been sent out with
 * the seqnr that we now have received the ack for.
 */
void vdp_ack_profiles(struct vdp_data *vd, int seqnr)
{
	struct vsi_profile *p;

	LIST_FOREACH(p, &vd->profile_head, profile) {
		if (p->seqnr == seqnr) {
			p->ackReceived = true;
			vdp_start_localchange_timer(p);
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
		if (p->localChange && (p->ackReceived == false))
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
	LLDPAD_DBG("%s(%i): setting profile->localChange to %s.\n",
		   __func__, __LINE__, (flag == true) ? "true" : "false");

	profile->localChange = flag;

	if (flag == true)
		vdp_start_localchange_timer(profile);
}

/* vdp_keepaliveTimer_expired - checks for expired ack timer
 * @profile: profile to be checked
 *
 * returns true or false
 *
 * returns value of profile->keepaliveTimerExpired, true if ack timer has expired,
 * false otherwise.
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

/* vdp_localchange_handler - triggers in case of ackReceived or on vdp localchange
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
void vdp_localchange_handler(void *eloop_data, void *user_ctx)
{
	struct vsi_profile *p;

	p = (struct vsi_profile *) user_ctx;

	if ((p->ackReceived) || (p->localChange)) {
		LLDPAD_DBG("%s(%i): p->localChange %i!\n",
			   __func__, __LINE__, p->localChange);
		LLDPAD_DBG("%s(%i): p->ackReceived %i!\n",
			   __func__, __LINE__, p->ackReceived);
		vdp_vsi_sm_station(p);
	}
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

	return eloop_register_timeout(0, usecs, vdp_localchange_handler, NULL, (void *) p);
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
void vdp_ack_timeout_handler(void *eloop_data, void *user_ctx)
{
	struct vsi_profile *p = (struct vsi_profile *) user_ctx;

	if (p->ackTimer > 0)
		p->ackTimer -= VDP_ACK_TIMER_DEFAULT;

	if (vdp_ackTimer_expired(p)) {
		LLDPAD_DBG("%s(%i): profile 0x%02x\n",
			   __func__, __LINE__, p->instance[15]);
		LLDPAD_DBG("%s(%i): vdp_ackTimer_expired %i\n",
			   __func__, __LINE__, vdp_ackTimer_expired(p));
		LLDPAD_DBG("%s(%i): p->ackReceived %i\n",
			   __func__, __LINE__, p->ackReceived);
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

	LLDPAD_DBG("%s(%i)-%s: starting ack timer for 0x%02x (%i)\n",
		   __func__, __LINE__, profile->port->ifname,
		   profile->instance[15], profile->ackTimer);

	return eloop_register_timeout(0, usecs, vdp_ack_timeout_handler, NULL, (void *) profile);
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
	LLDPAD_DBG("%s(%i)-%s: stopping ack timer for 0x%02x (%i)\n",
		   __func__, __LINE__, profile->port->ifname,
		   profile->instance[15], profile->ackTimer);

	return eloop_cancel_timeout(vdp_ack_timeout_handler, NULL, (void *) profile);
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
void vdp_keepalive_timeout_handler(void *eloop_data, void *user_ctx)
{
	struct vsi_profile *p = (struct vsi_profile *) user_ctx;

	if (p->keepaliveTimer > 0)
		p->keepaliveTimer -= VDP_KEEPALIVE_TIMER_DEFAULT;

	if (vdp_keepaliveTimer_expired(p)) {
		LLDPAD_DBG("%s(%i): profile 0x%02x\n",
			   __func__, __LINE__, p->instance[15]);
		LLDPAD_DBG("%s(%i): vdp_keepaliveTimer_expired %i\n",
			   __func__, __LINE__, vdp_keepaliveTimer_expired(p));
		LLDPAD_DBG("%s(%i): p->ackReceived %i\n",
			   __func__, __LINE__, p->ackReceived);
		vdp_vsi_sm_station(p);
	}
}

/* vdp_start_keepalive_timer - starts the VDP profile keepalive timer
 * @vd: vdp_data for the interface
 *
 * returns 0 on success, -1 on error
 *
 * starts the VDP profile keepalive timer when a profile has been handed to ecp for
 * transmission.
 */
static int vdp_start_keepaliveTimer(struct vsi_profile *profile)
{
	unsigned int usecs;

	usecs = VDP_KEEPALIVE_TIMER_DEFAULT;

	profile->keepaliveTimer = VDP_KEEPALIVE_TIMER_DEFAULT;

	LLDPAD_DBG("%s(%i)-%s: starting keepalive timer for 0x%02x (%i)\n",
		   __func__, __LINE__, profile->port->ifname,
		   profile->instance[15], profile->keepaliveTimer);

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

	LLDPAD_DBG("%s(%i)-%s: stopping keepalive timer for 0x%02x (%i)\n",
		   __func__, __LINE__, profile->port->ifname,
		   profile->instance[15], profile->keepaliveTimer);

	return eloop_cancel_timeout(vdp_keepalive_timeout_handler, NULL, (void *) profile);
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
		LLDPAD_ERR("ERROR: The VDP station State Machine is broken!\n");
		break;
	}

	LLDPAD_DBG("%s(%i)-%s: state change %s -> %s\n", __func__, __LINE__,
	       profile->port->ifname, vsi_states[profile->state], vsi_states[newstate]);

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
			vdp_vsi_change_station_state(profile, VSI_ASSOCIATED);
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
		LLDPAD_DBG("%s(%i): profile->ackReceived %i, vdp_ackTimer %i\n", __func__,
			   __LINE__, profile->ackReceived, profile->ackTimer);
		if (profile->ackReceived) {
			vdp_vsi_change_station_state(profile, VSI_PREASSOCIATED);
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

	vdp_vsi_set_station_state(profile);
	do {
		LLDPAD_DBG("%s(%i)-%s: station for 0x%02x - %s\n",
			   __func__, __LINE__, profile->port->ifname,
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
			vdp_stop_ackTimer(profile);
			vdp_stop_keepaliveTimer(profile);
			vdp_remove_profile(profile);
			break;
		default:
			LLDPAD_ERR("%s: VSI state machine in invalid state %d\n",
				   vd->ifname, profile->state);
		}
	} while (vdp_vsi_set_station_state(profile) == true);

}

/* vdp_vsi_change_bridge_state - changes the VDP bridge sm state
 * @profile: profile to process
 * @newstate: new state for the sm
 *
 * no return value
 *
 * actually changes the state of the profile
 */
static void vdp_vsi_change_bridge_state(struct vsi_profile *profile, u8 newstate)
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
		LLDPAD_ERR("ERROR: The VDP bridge State Machine is broken!\n");
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
		if ((profile->mode == VDP_MODE_DEASSOCIATE)) /* || (INACTIVE)) */ {
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
		LLDPAD_ERR("%s: VSI state machine (bridge) in invalid state %d\n",
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
		LLDPAD_DBG("%s(%i)-%s: bridge - %s\n", __func__, __LINE__,
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
			LLDPAD_DBG("%s(%i)-%s: framein %p, sizein %i\n", __func__, __LINE__,
			       profile->port->ifname, vd->ecp.rx.framein,
			       vd->ecp.rx.sizein);
			ecp_rx_send_ack_frame(vd);
			break;
		case VSI_PREASSOCIATED:
			LLDPAD_DBG("%s(%i)-%s: \n", __func__, __LINE__, profile->port->ifname);
			break;
		case VSI_DEASSOC_PROCESSING:
			/* TODO: txTLV(DeAssoc ACK) */
			break;
		case VSI_EXIT:
			vdp_remove_profile(profile);
			break;
		default:
			LLDPAD_ERR("%s: VSI state machine in invalid state %d\n",
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
static int vdp_validate_tlv(struct tlv_info_vdp *vdp)
{
	if (ntoh24(vdp->oui) != OUI_IEEE_8021Qbg) {
		LLDPAD_DBG("vdp->oui %06x \n", ntoh24(vdp->oui));
		goto out_err;
	}

	if (vdp->sub != LLDP_VDP_SUBTYPE) {
		LLDPAD_DBG("vdp->sub %02x \n", vdp->sub);
		goto out_err;
	}

	if ((vdp->mode < VDP_MODE_PREASSOCIATE) ||
		(vdp->mode > VDP_MODE_DEASSOCIATE)) {
		LLDPAD_DBG("Unknown mode %02x in vsi tlv !\n", vdp->mode);
		goto out_err;
	}

	if ((vdp->response < VDP_RESPONSE_SUCCESS) ||
		(vdp->response > VDP_RESPONSE_OUT_OF_SYNC)) {
		LLDPAD_DBG("Unknown response %02x \n", vdp->response);
		goto out_err;
	}

	if (vdp->format != VDP_MACVLAN_FORMAT_1) {
		LLDPAD_DBG("Unknown format %02x in vsi tlv !\n", vdp->format);
		goto out_err;
	}

	if (ntohs(vdp->entries) != 1) {
		LLDPAD_DBG("Multiple entries %02x in vsi tlv !\n", vdp->entries);
		goto out_err;
	}

	return 0;

out_err:
	return 1;
}

/*
 * vdp_indicate - receive VSI TLVs from ECP
 * @port: the port on which the tlv was received
 * @tlv: the unpacked tlv to receive
 * @ecp_mode: the mode under which the tlv was received (ACK or REQ)
 *
 * Returns 0 on success
 *
 * receives a vsi tlv and creates a profile. Take appropriate action
 * depending on the role of the (receive) port
 */
int vdp_indicate(struct vdp_data *vd, struct unpacked_tlv *tlv, int ecp_mode)
{
	struct tlv_info_vdp *vdp;
	struct vsi_profile *p, *profile;
	struct port *port = port_find_by_name(vd->ifname);

	LLDPAD_DBG("%s(%i): indicating vdp for %s !\n", __func__, __LINE__, vd->ifname);

	if (!port) {
		LLDPAD_ERR("%s(%i): port not found for %s !\n", __func__, __LINE__, vd->ifname);
		goto out_err;
	}

	vdp = malloc(sizeof(struct tlv_info_vdp));

	if (!vdp) {
		LLDPAD_ERR("%s(%i): unable to allocate vdp !\n", __func__, __LINE__);
		goto out_err;
	}

	memset(vdp, 0, sizeof(struct tlv_info_vdp));
	memcpy(vdp, tlv->info, tlv->length);

	if (vdp_validate_tlv(vdp)) {
		LLDPAD_ERR("%s(%i): Invalid TLV received !\n", __func__, __LINE__);
		goto out_vdp;
	}

	profile = malloc(sizeof(struct vsi_profile));

	 if (!profile) {
		LLDPAD_ERR("%s(%i): unable to allocate profile !\n", __func__, __LINE__);
		goto out_vdp;
	 }

	memset(profile, 0, sizeof(struct vsi_profile));

	profile->mode = vdp->mode;
	profile->response = vdp->response;

	profile->mgrid = vdp->mgrid;
	profile->id = ntoh24(vdp->id);
	profile->version = vdp->version;
	memcpy(&profile->instance, &vdp->instance, 16);
	memcpy(&profile->mac, &vdp->mac_vlan.mac, MAC_ADDR_LEN);
	profile->vlan = ntohs(vdp->mac_vlan.vlan);

	profile->port = port;

	if (vd->role == VDP_ROLE_STATION) {
		/* do we have the profile already ? */
		LIST_FOREACH(p, &vd->profile_head, profile) {
			if (vdp_profile_equal(p, profile)) {
				LLDPAD_DBG("%s(%i): station: profile found, "
					   "localChange %i ackReceived %i!\n",
					   __func__, __LINE__,
					   p->localChange, p->ackReceived);

				p->ackReceived = true;
				p->keepaliveTimer = VDP_KEEPALIVE_TIMER_DEFAULT;
				if (vdp->mode != p->mode) {
					p->mode = vdp->mode;
					p->remoteChange = true;
					LLDPAD_DBG("%s(%i): station: remoteChange %i !\n",
						   __func__, __LINE__, p->remoteChange);
				}
				p->response = vdp->response;

				if (vdp_vsi_negative_response(p))
					p->mode = VDP_MODE_DEASSOCIATE;

				LLDPAD_DBG("%s(%i): profile response: %s (%i) "
					   "for profile 0x%02x at state %s.\n",
					   __func__, __LINE__,
					   vdp_response2str(p->response),
					   p->response, p->instance[15],
					   vsi_states[p->state]);
				free(profile);
			} else {
				LLDPAD_DBG("%s(%i): station: profile not found !\n",
					   __func__, __LINE__);
				/* ignore profile */
			}
		}
	}

	if (vd->role == VDP_ROLE_BRIDGE) {
		/* do we have the profile already ? */
		LIST_FOREACH(p, &vd->profile_head, profile) {
			if (vdp_profile_equal(p, profile)) {
				break;
			}
		}

		if (p) {
			LLDPAD_DBG("%s(%i): bridge: profile found !\n", __func__, __LINE__);
		} else {
			LLDPAD_DBG("%s(%i): bridge: profile not found !\n", __func__, __LINE__);
			/* put it in the list  */
			profile->state = VSI_UNASSOCIATED;
			LIST_INSERT_HEAD(&vd->profile_head, profile, profile );
		}

		vdp_vsi_sm_bridge(profile);
	}

	return 0;

out_vdp:
	free(vdp);
out_err:
	LLDPAD_ERR("%s(%i): error !\n", __func__, __LINE__);
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
	int rc = 0;
	struct unpacked_tlv *tlv = NULL;
	struct tlv_info_vdp vdp;

	FREE_UNPKD_TLV(vd, vdp);

	memset(&vdp, 0, sizeof(vdp));

	hton24(vdp.oui, OUI_IEEE_8021Qbg);
	vdp.sub = LLDP_VDP_SUBTYPE;
	vdp.mode = profile->mode;
	vdp.response = 0;
	vdp.mgrid = profile->mgrid;
	hton24(vdp.id, profile->id);
	vdp.version = profile->version;
	memcpy(&vdp.instance,&profile->instance, 16);
	vdp.format = VDP_MACVLAN_FORMAT_1;
	vdp.entries = htons(1);
	memcpy(&vdp.mac_vlan.mac,&profile->mac, MAC_ADDR_LEN);
	vdp.mac_vlan.vlan = htons(profile->vlan);

	tlv = create_tlv();
	if (!tlv)
		goto out_err;

	tlv->type = ORG_SPECIFIC_TLV;
	tlv->length = sizeof(vdp);
	tlv->info = (u8 *)malloc(tlv->length);
	if(!tlv->info) {
		free(tlv);
		tlv = NULL;
		rc = ENOMEM;
		goto out_err;
	}
	memcpy(tlv->info, &vdp, tlv->length);

	vd->vdp = tlv;

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
	int rc = 0;

	if (!port_find_by_name(vd->ifname)) {
		rc = EEXIST;
		goto out_err;
	}

	if (vdp_bld_vsi_tlv(vd, profile)) {
		LLDPAD_ERR("%s:%s:vdp_bld_vsi_tlv() failed\n",
				__func__, vd->ifname);
		rc = EINVAL;
		goto out_err;
	}

out_err:
	return rc;
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
		LLDPAD_ERR("%s:%s vdp_bld_tlv failed\n",
			__func__, vd->ifname);
		goto out_err;
	}

	size = TLVSIZE(vd->vdp);

	if (!size) {
		LLDPAD_ERR("%s(%i): size %i of unpacked_tlv not correct !\n", __func__, __LINE__,
		       size);
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
	LLDPAD_ERR("%s:%s: failed\n", __func__, vd->ifname);
	return NULL;
}

/* vdp_profile_equal - checks for equality of 2 profiles
 * @p1: profile 1
 * @p2: profile 2
 *
 * returns 1 on success, 0 on error
 *
 * compares mgrid, id, version, instance, mac and vlan of 2 profiles to find
 * out if they are equal.
 */
int vdp_profile_equal(struct vsi_profile *p1, struct vsi_profile *p2)
{
	if (p1->mgrid != p2->mgrid)
		return 0;

	if (p1->id != p2->id)
		return 0;

	if (p1->version != p2->version)
		return 0;

	if (memcmp(p1->instance, p2->instance, 16))
		return 0;

	if (memcmp(p1->mac, p2->mac, MAC_ADDR_LEN))
		return 0;

	if (p1->vlan != p2->vlan)
		return 0;

	return 1;
}

/* vdp_add_profile - adds a profile to a per port list
 * @profile: profile to add
 *
 * returns the profile that has been found or added, NULL otherwise.
 *
 * main interface function which adds a profile to a list kept on a per-port
 * basis. Checks if the profile is already in the list, adds it if necessary.
 */
struct vsi_profile *vdp_add_profile(struct vsi_profile *profile)
{
	struct vsi_profile *p;
	struct vdp_data *vd;

	LLDPAD_DBG("%s(%i): adding vdp profile for %s !\n", __func__, __LINE__,
	       profile->port->ifname);

	vd = vdp_data(profile->port->ifname);
	if (!vd) {
		LLDPAD_ERR("%s(%i): Could not find vdp_data for %s !\n", __func__, __LINE__,
		       profile->port->ifname);
		return NULL;
	}

	profile->response = VDP_RESPONSE_NO_RESPONSE;

	vdp_print_profile(profile);

	/* loop over all existing profiles and check wether
	 * one for this combination already exists. If yes, check,
	 * if the MAC/VLAN pair already exists. If not, add it.
	 * Note: currently only one MAC/VLAN pair supported ! */
	LIST_FOREACH(p, &vd->profile_head, profile) {
		if (p) {
			if (vdp_profile_equal(p, profile)) {
				if (p->mode == profile->mode) {
					LLDPAD_DBG("%s(%i): profile already exists, ignoring !\n",
					       __func__, __LINE__);
				} else {
					LLDPAD_DBG("%s(%i): taking new mode !\n", __func__,
					       __LINE__);
					p->mode = profile->mode;
				}

				vdp_somethingChangedLocal(p, true);

				return p;
			}
		}
	}

	LIST_INSERT_HEAD(&vd->profile_head, profile, profile );

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

	LLDPAD_DBG("%s(%i): removing vdp profile on %s !\n", __func__, __LINE__,
	       profile->port->ifname);

	vd = vdp_data(profile->port->ifname);
	if (!vd) {
		LLDPAD_ERR("%s(%i): Could not find vdp_data for %s !\n", __func__, __LINE__,
		       profile->port->ifname);
		return -1;
	}

	/* loop over all existing profiles and check wether
	 * it exists. If yes, remove it. */
	LIST_FOREACH(p, &vd->profile_head, profile) {
		if (p) {
			if (vdp_profile_equal(p, profile)) {
				vdp_print_profile(p);
				LIST_REMOVE(p, profile);
				free(p);
			}
		} else {
			return -1;
		}
	}

	return 0;
}

/* vdp_ifdown - tear down vdp structures for a interface
 * @ifname: name of the interface
 *
 * no return value
 *
 * interface function to lldpad. tears down vdp specific structures if
 * interface "ifname" goes down.
 */
void vdp_ifdown(char *ifname)
{
	struct vdp_data *vd;
	struct vsi_profile *p;

	LLDPAD_DBG("%s called on interface %s !\n", __func__, ifname);

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

	LLDPAD_INFO("%s:%s vdp data removed\n", __func__, ifname);
	return;
out_err:
	LLDPAD_ERR("%s:%s vdp data remove failed\n", __func__, ifname);

	return;
}

/* vdp_ifup - build up vdp structures for a interface
 * @ifname: name of the interface
 *
 * no return value
 *
 * interface function to lldpad. builds up vdp specific structures if
 * interface "ifname" goes down.
 */
void vdp_ifup(char *ifname)
{
	char *string;
	struct vdp_data *vd;
	struct vdp_user_data *ud;
	struct port *port;
	struct vsi_profile *p;

	/* VDP does not support bonded devices */
	if (is_bond(ifname))
		return;

	LLDPAD_DBG("%s(%i): starting VDP for if %s !\n", __func__, __LINE__, ifname);

	vd = vdp_data(ifname);
	if (vd) {
		LLDPAD_WARN("%s:%s vdp data already exists !\n", __func__, ifname);
		goto out_start_again;
	}

	/* not found, alloc/init per-port module data */
	vd = (struct vdp_data *) calloc(1, sizeof(struct vdp_data));
	if (!vd) {
		LLDPAD_ERR("%s:%s malloc %ld failed\n",
			 __func__, ifname, sizeof(*vd));
		goto out_err;
	}
	strncpy(vd->ifname, ifname, IFNAMSIZ);

	vd->role = VDP_ROLE_STATION;

	if (!get_cfg(ifname, "vdp.role", (void *)&string,
		    CONFIG_TYPE_STRING)) {
		if (!strcasecmp(string, VAL_BRIDGE)) {
			vd->role = VDP_ROLE_BRIDGE;
		}
	}

	LLDPAD_DBG("%s: configured for %s mode !\n", ifname,
	       (vd->role ==VDP_ROLE_BRIDGE) ? "bridge" : "station");

	LIST_INIT(&vd->profile_head);

	ud = find_module_user_data_by_id(&lldp_head, LLDP_MOD_VDP);
	LIST_INSERT_HEAD(&ud->head, vd, entry);

	port = port_find_by_name(ifname);

	if (!port) {
		LLDPAD_ERR("%s(%i): could not find port for %s!\n",
			   __func__, __LINE__, ifname);
		goto out_err;
	}

	if (port->adminStatus != enabledRxTx) {
		LLDPAD_WARN("%s(%i): port %s not enabled for RxTx (%i) !\n",
			    __func__, __LINE__, ifname, port->adminStatus);
		return;
	}

out_start_again:
	if (ecp_init(ifname)) {
		LLDPAD_ERR("%s:%s unable to init ecp !\n", __func__, ifname);
		vdp_ifdown(ifname);
		goto out_err;
	}

	vd->keepaliveTimer = VDP_KEEPALIVE_TIMER_DEFAULT;
	vd->ackTimer = VDP_ACK_TIMER_DEFAULT;

	LLDPAD_DBG("%s(%i)-%s: starting vdp timer (%i)\n", __func__, __LINE__,
	       vd->ifname, vd->nroftimers);

	LIST_FOREACH(p, &vd->profile_head, profile) {
		if (p->ackTimer > 0) {
			vdp_somethingChangedLocal(p, true);
			vdp_start_ackTimer(p);
		}
		if (p->keepaliveTimer > 0)
			vdp_start_keepaliveTimer(p);
	}

	LLDPAD_DBG("%s:%s vdp added\n", __func__, ifname);
	return;

out_err:
	LLDPAD_ERR("%s:%s vdp adding failed\n", __func__, ifname);
	return;
}

static const struct lldp_mod_ops vdp_ops =  {
	.lldp_mod_register	= vdp_register,
	.lldp_mod_unregister	= vdp_unregister,
	.lldp_mod_ifup		= vdp_ifup,
	.lldp_mod_ifdown	= vdp_ifdown,
	.get_arg_handler	= vdp_get_arg_handlers,
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
		LLDPAD_ERR("lldpad failed to start - failed to malloc module data\n");
		goto out_err;
	}
	ud = malloc(sizeof(struct vdp_user_data));
	if (!ud) {
		free(mod);
		LLDPAD_ERR("lldpad failed to start - failed to malloc module user data\n");
		goto out_err;
	}
	LIST_INIT(&ud->head);
	mod->id = LLDP_MOD_VDP;
	mod->ops = &vdp_ops;
	mod->data = ud;
	LLDPAD_DBG("%s:done\n", __func__);
	return mod;

out_err:
	LLDPAD_ERR("%s:failed\n", __func__);
	return NULL;
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
	LLDPAD_DBG("%s:done\n", __func__);
}


