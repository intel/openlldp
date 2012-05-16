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

#ifndef _DRV_CFG_H
#define _DRV_CFG_H
#include <stdbool.h>

/* DCB configuration commands */
enum {
        DCB_C_UNDEFINED,
        DCB_C_GSTATE,
        DCB_C_SSTATE,
        DCB_C_PG_STATS,
        DCB_C_PGTX_GCFG,
        DCB_C_PGTX_SCFG,
        DCB_C_PGRX_GCFG,
        DCB_C_PGRX_SCFG,
        DCB_C_PFC_GCFG,
        DCB_C_PFC_SCFG,
        DCB_C_PFC_STATS,
	DCB_C_GLINK_SPD,
	DCB_C_SLINK_SPD,
	DCB_C_SET_ALL,
	DCB_C_GPERM_HWADDR,
        __DCB_C_ENUM_MAX,
};

#define IXGBE_DCB_C_MAX               (__DCB_C_ENUM_MAX - 1)

/* DCB configuration attributes */
enum {
	DCB_A_UNDEFINED = 0,
	DCB_A_IFNAME,
	DCB_A_STATE,
	DCB_A_PFC_STATS,
	DCB_A_PFC_CFG,
	DCB_A_PG_STATS,
	DCB_A_PG_CFG,
	DCB_A_LINK_SPD,
	DCB_A_SET_ALL,
	DCB_A_PERM_HWADDR,
	__DCB_A_ENUM_MAX,
};

#define IXGBE_DCB_A_MAX               (__DCB_A_ENUM_MAX - 1)

/* PERM HWADDR attributes */
enum {
        PERM_HW_A_UNDEFINED,
        PERM_HW_A_0,
        PERM_HW_A_1,
        PERM_HW_A_2,
        PERM_HW_A_3,
        PERM_HW_A_4,
        PERM_HW_A_5,
        PERM_HW_A_ALL,
        __PERM_HW_A_ENUM_MAX,
};

#define IXGBE_DCB_PERM_HW_A_MAX        (__PERM_HW_A_ENUM_MAX - 1)

/* PFC configuration attributes */
enum {
	PFC_A_UP_UNDEFINED,
	PFC_A_UP_0,
	PFC_A_UP_1,
	PFC_A_UP_2,
	PFC_A_UP_3,
	PFC_A_UP_4,
	PFC_A_UP_5,
	PFC_A_UP_6,
	PFC_A_UP_7,
	PFC_A_UP_MAX, /* Used as an iterator cap */
	PFC_A_UP_ALL,
	__PFC_A_UP_ENUM_MAX,
};

#define IXGBE_DCB_PFC_A_UP_MAX (__PFC_A_UP_ENUM_MAX - 1)

/* Priority Group Traffic Class and Bandwidth Group
 * configuration attributes */
enum {
        PG_A_UNDEFINED,
        PG_A_TC_0,
        PG_A_TC_1,
        PG_A_TC_2,
        PG_A_TC_3,
        PG_A_TC_4,
        PG_A_TC_5,
        PG_A_TC_6,
        PG_A_TC_7,
        PG_A_TC_MAX, /* Used as an iterator cap */
        PG_A_TC_ALL,
        PG_A_BWG_0,
        PG_A_BWG_1,
        PG_A_BWG_2,
        PG_A_BWG_3,
        PG_A_BWG_4,
        PG_A_BWG_5,
        PG_A_BWG_6,
        PG_A_BWG_7,
        PG_A_BWG_MAX, /* Used as an iterator cap */
        PG_A_BWG_ALL,
        __PG_A_ENUM_MAX,
};

#define IXGBE_DCB_PG_A_MAX     (__PG_A_ENUM_MAX - 1)


enum {
	TC_A_PARAM_UNDEFINED,
	TC_A_PARAM_STRICT_PRIO,
	TC_A_PARAM_BW_GROUP_ID,
	TC_A_PARAM_BW_PCT_IN_GROUP,
	TC_A_PARAM_UP_MAPPING,
	TC_A_PARAM_MAX, /* Used as an iterator cap */
	TC_A_PARAM_ALL,
	__TC_A_PARAM_ENUM_MAX,
};

#define IXGBE_DCB_TC_A_PARAM_MAX (__TC_A_PARAM_ENUM_MAX - 1)

#define IXGBE_NLTYPE_DCB_NAME         "IXGBE_DCB"

enum strict_prio_type {
	prio_none = 0,
	prio_group,
	prio_link
};

struct tc_config {
	__u8 bwgid;
	__u8 up_to_tc_bitmap;
	__u8 prio_type;
	__u8 tc_percent;
};

/* Data structures (and macros) needed that are not including in any library. */
#define NLA_HDRLEN           ((int) NLA_ALIGN(sizeof(struct nlattr)))
#define NLA_DATA(nla)        ((void *)((char*)(nla) + NLA_HDRLEN))
#define NLA_PAYLOAD(len)     (len - NLA_HDRLEN)

/* Maximum size of response requested or message sent */
#define MAX_MSG_SIZE	4096 

int deinit_drv_if(void);

int get_perm_hwaddr(const char *ifname, u8 *buf_perm, u8 *buf_san);
int set_hw_all(char *ifname);
int set_hw_state(char *device_name, int dcb_state);
int get_hw_state(char *device_name, int *dcb_state);
int init_drv_if(void);
bool check_port_dcb_mode(char *device_name);
int set_dcbx_mode(char *ifname, __u8 mode);

#endif
