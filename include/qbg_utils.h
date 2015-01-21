/*******************************************************************************

  Implementation of EVB TLVs for LLDP
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

*******************************************************************************/

/*
 * Header file for small utility functions called throught qbg modules.
 */

#ifndef QBG_UTILS_H
#define QBG_UTILS_H

void hexdump_frame(const char *, char *, const unsigned char *, size_t);
int modules_notify(int, int, char *, void *);

/*
 * Required buffer space to display a VSI ID (as UUID or other formats).
 * VDP_UUID_STRLEN = strlen("fa9b7fff-b0a0-4893-abcd-beef4ff18f8f")
 *                or strlen("fa9b:7fff:b0a0:4893:abcd:beef:4ff1:8f8f")
 */
#define VDP_UUID_STRLEN 40

/* Convert VSI IDs to strings */
int vdp_uuid2str(const unsigned char *, char *, size_t);
int vdp_str2uuid(unsigned char *, char *, size_t);
#endif
