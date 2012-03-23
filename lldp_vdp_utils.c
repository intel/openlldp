/******************************************************************************

  Implementation of VDP according to IEEE 802.1Qbg
  (c) Copyright IBM Corp. 2012

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
 * This file contains utilities and support functions for the VDP protocol.
 */

#include <stdlib.h>
#include "lldp_vdp.h"

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

	LIST_FOREACH(p, &profile->macvid_head, entry) {
		LIST_REMOVE(p, entry);
		free(p);
	}
}

void vdp_delete_profile(struct vsi_profile *prof)
{
	vdp_remove_macvlan(prof);
	free(prof);
}
