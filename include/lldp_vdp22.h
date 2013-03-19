/*******************************************************************************

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

*******************************************************************************/

/*
 * External interface definition for the ratified standard VDP protocol.
 */
#ifndef LLDP_VDP22_H
#define LLDP_VDP22_H

#include	<sys/queue.h>
#include	<linux/if_ether.h>

#include	"lldp_mod.h"

struct vsi22_profile {
	LIST_ENTRY(vsi22_profile) prof22_entry;
};

struct vdp22 {		/* Per interface VSI/VDP data */
	char ifname[IFNAMSIZ];		/* Interface name */
	unsigned char max_rwd;		/* Max number of resource wait delay */
	unsigned char max_rka;		/* Max number of reinit keep alive */
	unsigned char gpid;		/* Supports group ids in VDP */
	unsigned short input_len;	/* Length of input data from ECP */
	unsigned char input[ETH_DATA_LEN];	/* Input data from ECP */
	LIST_HEAD(profile22_head, vsi22_profile) prof22_head;
	LIST_ENTRY(vdp22) entry;
};

struct vdp22_user_data {		/* Head for all VDP data */
	LIST_HEAD(vdp22_head, vdp22) head;
};

struct lldp_module *vdp22_register(void);
void vdp22_unregister(struct lldp_module *);
void vdp22_start(const char *);
void vdp22_stop(char *);
int vdp22_query(const char *);

#endif
