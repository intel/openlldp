/*******************************************************************************

  Implementation of OUI for VDP2.2
  Copyright (c) 2012-2014 by Cisco Systems, Inc.

  Author(s): Padmanabhan Krishnan <padkrish at cisco dot com>

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

#ifndef __VDP22_OUI_H__
#define __VDP22_OUI_H__

#include <stdbool.h>

/*
 * Generic OUI related defines
 */
enum vdp22_oui {
	VDP22_OUI_TYPE_LEN = 3,          /* Size of OUI Type field */
	MAX_NUM_OUI = 10,
	VDP22_OUI_MAX_NAME = 20,
	MAX_OUI_DATA_LEN = 200
};

struct vdp22_oui_data_s {
	void *vsi_data;
	unsigned char oui_type[VDP22_OUI_TYPE_LEN];
	char oui_name[VDP22_OUI_MAX_NAME];
	int len;
	void *data;
};

typedef struct vdptool_oui_data_s {
	char oui_name[VDP22_OUI_MAX_NAME];
	char data[MAX_OUI_DATA_LEN];
} vdptool_oui_data_t;

typedef struct vdptool_oui_hndlr_tbl_s {
	char *oui_name;
	bool (*oui_cli_encode_hndlr)(char *dst, char *src, size_t len);
} vdptool_oui_hndlr_tbl_t;

struct vdpnl_oui_data_s {
	unsigned char oui_type[VDP22_OUI_TYPE_LEN];
	char oui_name[VDP22_OUI_MAX_NAME];
	int len;
	char data[MAX_OUI_DATA_LEN];
	/* If vdpnl structure is used for IPC, then this cannot be a ptr as
	 * otherwise it needs to be flattened out. If this is just used within
	 * lldpad then this can be made a ptr instead of a static array.
	 * May need to revisit later TODO
	 */
};

struct vdp22_oui_init_s {
	unsigned char oui_type[VDP22_OUI_TYPE_LEN];
	char oui_name[VDP22_OUI_MAX_NAME];
	bool (*oui_init)();
};

struct vdp22_oui_handler_s {
	unsigned char oui_type[VDP22_OUI_TYPE_LEN];
	char oui_name[VDP22_OUI_MAX_NAME];
	/* This handler converts the OUI string to vdpnl structure */
	bool (*str2vdpnl_hndlr)(struct vdpnl_oui_data_s *, char *);
	/* This handler converts the vdpnl structure to vsi22 structure */
	bool (*vdpnl2vsi22_hndlr)(void *, struct vdpnl_oui_data_s *,
				   struct vdp22_oui_data_s *);
	/* This handler creates the OUI fields for Tx */
	size_t (*vdp_tx_hndlr)(char unsigned *,
				struct vdp22_oui_data_s *, size_t);
	/* This handler is called for processing/Rx the OUI information */
	bool (*vdp_rx_hndlr)();
	/* This handler frees the OUI structures */
	bool (*vdp_free_oui_hndlr)(struct vdp22_oui_data_s *);
	/* This handler returns the size of OUI PTLV */
	unsigned long (*oui_ptlv_size_hndlr)(void *);
};

#endif /* __VDP22_OUI_H__ */
