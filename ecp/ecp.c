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

	vd->ecp.ackTimerExpired = true;
	ecp_tx_run_sm(vd);
	ecp_rx_run_sm(vd);

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

	ecp_tx_stop_ackTimer(vd);

	return 0;

fail:
	return -1;
}
