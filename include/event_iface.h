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

#ifndef  _EVENT_IFACE_H_ 
#define  _EVENT_IFACE_H_

int event_iface_init(void);
int event_iface_init_user_space(void);
int event_iface_deinit(void);
int oper_add_device(char *device_name);

void sendto_event_iface(char *buf, int len);

/* index for event interface socket pair usage
*/
#define EVENT_IF_READ  0
#define EVENT_IF_WRITE 1

#endif /* _EVENT_IFACE_H_ */
