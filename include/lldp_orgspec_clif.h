/*******************************************************************************

  Implementation of Organisation Specific TLVs for LLDP
  (c) Copyright SuSE Linux Products GmbH 2011

  Author(s): Hannes Reinecke <hare at suse dot de>

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

#ifndef _LLDP_ORGSPEC_CLIF_H
#define _LLDP_ORGSPEC_CLIF_H

struct lldp_module *orgspec_cli_register(void);
void orgspec_cli_unregister(struct lldp_module *);
int orgspec_print_tlv(u32, u16, char *);

#endif /* _LLDP_ORGSPEC_CLIF_H */
