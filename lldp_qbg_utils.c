/******************************************************************************

  Implementation of ECP according to 802.1Qbg
  (c) Copyright IBM Corp. 2010, 2013

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
 * This file contains common support utilities for the ECP protocols.
 */

#include <stdio.h>
#include <linux/if_ether.h>

#include "lldp.h"
#include "lldp_mod.h"
#include "messages.h"
#include "lldp_qbg_utils.h"

extern int loglvl;			/* Global lldpad log level */
extern struct lldp_head lldp_head;

/*
 * hexdump_frame - print raw evb/ecp/vdp frame
 */
void hexdump_frame(const char *ifname, char *txt, const unsigned char *buf,
		   size_t len)
{
	size_t i;
	int left = 0;
	char buffer[ETH_FRAME_LEN * 3];

	/* Only collect data when the loglvl ensures data printout */
	if (LOG_DEBUG < loglvl)
		return;
	for (i = 0; i < len; i++) {
		int c;
		c = snprintf(buffer + left, sizeof buffer - left, "%02x%c",
			     buf[i], !((i + 1) % 16) ? '\n' : ' ');
		if (c > 0 && (c < (int)sizeof buffer - left))
			left += c;
	}
	LLDPAD_DBG("%s:%s %s\n%s\n", __func__, ifname, txt, buffer);
}

/*
 * Function to advertise changed variables to other modules.
 *
 * Parameters are interface name, target module id and data.
 * When sending the data, the module call back function contains the
 * module id of the sender.
 *
 * Return 0 when no addressee found or addressess found but addressee was
 * unable to handle data.
 */
int modules_notify(int id, int sender_id, char *ifname, void *data)
{
	struct lldp_module *mp = find_module_by_id(&lldp_head, id);
	int rc = 0;

	if (mp && mp->ops->lldp_mod_notify)
		rc = mp->ops->lldp_mod_notify(sender_id, ifname, data);
	LLDPAD_DBG("%s:%s target-id:%#x rc:%d\n", __func__, ifname, id, rc);
	return rc;
}

int vdp_uuid2str(const u8 *p, char *dst, size_t size)
{
	if (dst && size > VDP_UUID_STRLEN) {
		snprintf(dst, size, "%02x%02x%02x%02x-%02x%02x-%02x%02x"
			 "-%02x%02x-%02x%02x%02x%02x%02x%02x",
			 p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
			 p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
		return 0;
	}
	return -1;
}
