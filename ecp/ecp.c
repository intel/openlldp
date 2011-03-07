/*******************************************************************************

  implementation of ECP according to 802.1Qbg
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

#include <net/if.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <linux/if_bridge.h>
#include "lldp.h"
#include "lldp_evb.h"
#include "lldp_vdp.h"
#include "messages.h"
#include "config.h"
#include "lldp/l2_packet.h"
#include "ecp/ecp.h"

static int ecp_start_timer(struct vdp_data *vd);

/* ecp_timeout_handler - handles the timer expiry
 * @eloop_data: data structure of event loop
 * @user_ctx: user context, vdp_data here
 *
 * no return value
 *
 * called when the ECP timer has expired. Calls the ECP station state machine.
 */
void ecp_timeout_handler(void *eloop_data, void *user_ctx)
{
	struct vdp_data *vd;

	vd = (struct vdp_data *) user_ctx;

	if (vd->ecp.ackTimer > 0)
		vd->ecp.ackTimer--;

	if ((ecp_ackTimer_expired(vd) == true) ||
	    vd->ecp.tx.localChange) {
		LLDPAD_DBG("%s(%i)-%s: ecp_ackTimer_expired (%i) !\n",
			   __func__, __LINE__, vd->ifname, vd->ecp.ackTimer);
		LLDPAD_DBG("%s(%i)-%s: ecp.tx.localChange %i!\n",
			   __func__, __LINE__,
			   vd->ifname, vd->ecp.tx.localChange);
		ecp_tx_run_sm(vd);
	}

	ecp_start_timer(vd);
}

/* ecp_start_timer - starts the ECP timer
 * @vd: vdp_data for the interface
 *
 * returns 0 on success, -1 on error
 *
 * starts the ECP timer when the interface comes up.
 */
static int ecp_start_timer(struct vdp_data *vd)
{
	unsigned int secs, usecs;

	secs = 0;
	usecs = ECP_TIMER_GRANULARITY;

	return eloop_register_timeout(secs, usecs, ecp_timeout_handler, NULL, (void *) vd);
}

/* ecp_stop_timer - stop the ECP timer
 * @vd: vdp_data for the interface
 *
 * returns the number of removed handlers
 *
 * stops the ECP timer. Used e.g. when the host interface goes down.
 */
static int ecp_stop_timer(struct vdp_data *vd)
{
	LLDPAD_DBG("%s(%i)-%s: stopping ecp timer\n", __func__, __LINE__,
	       vd->ifname);

	return eloop_cancel_timeout(ecp_timeout_handler, NULL, (void *) vd);
}

/* ecp_init - initialize ecp module
 * @ifname: interface for which the module is initialized
 *
 * returns 0 on success, -1 on error
 *
 * finds the port to the interface name, sets up the receive handle for
 * incoming ecp frames and initializes the ecp rx and tx state machines.
 * should usually be called when a successful exchange of EVB TLVs has been
 * made and ECP and VDP protocols are supported by both sides.
 */
int ecp_init(char *ifname)
{
	struct vdp_data *vd;

	LLDPAD_DBG("%s(%i): starting ECP for if %s !\n", __func__, __LINE__, ifname);

	vd = vdp_data(ifname);

	if (!vd) {
		LLDPAD_ERR("%s(%i): unable to find vd %s ! \n", __func__, __LINE__, ifname);
		goto fail;
	}

	if (!vd->ecp.l2) {
		vd->ecp.l2 = l2_packet_init(vd->ifname, NULL, ETH_P_ECP,
					    ecp_rx_ReceiveFrame, vd, 1);
	}

	if (!vd->ecp.l2) {
		LLDPAD_ERR("ERROR: Failed to open register layer 2 access to "
			"ETH_P_ECP\n");
		goto fail;
	}

	ecp_rx_change_state(vd, ECP_RX_IDLE);
	ecp_rx_run_sm(vd);

	ecp_start_timer(vd);

	return 0;

fail:
	return -1;
}

int ecp_deinit(char *ifname)
{
	struct vdp_data *vd;

	LLDPAD_DBG("%s(%i): stopping ECP for if %s !\n", __func__, __LINE__, ifname);

	vd = vdp_data(ifname);

	if (!vd) {
		LLDPAD_ERR("%s(%i): unable to find vd %s ! \n", __func__, __LINE__, ifname);
		goto fail;
	}

	ecp_stop_timer(vd);
	ecp_tx_stop_ackTimer(vd);

	return 0;

fail:
	return -1;
}
