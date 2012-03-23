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
