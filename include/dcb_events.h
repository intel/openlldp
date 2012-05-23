/*******************************************************************************

  LLDP Agent Daemon (LLDPAD) Software
  Copyright(c) 2007-2012 Intel Corporation.

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

  Contact Information:
  open-lldp Mailing List <lldp-devel@open-lldp.org>

*******************************************************************************/

#ifndef _DCB_EVENTS_H_
#define _DCB_EVENTS_H_

#define EVENT_OPERMODE 0x0001    /* Operational mode changed */
#define EVENT_OPERATTR 0x0002    /* Operational configuration changed */

void pg_event(char *dn, u32 events);
void pfc_event(char *dn, u32 events);
void app_event(char *dn, u32 subtype, u32 events);
void llink_event(char *dn, u32 subtype, u32 events);

#endif   /* _DCB_EVENTS_H_ */
