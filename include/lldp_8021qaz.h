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

#ifndef _LLDP_8021QAZ_H
#define _LLDP_8021QAZ_H

#include "lldp.h"
#include "lldp_mod.h"
#include "lldp_tlv.h"
#include "linux/dcbnl.h"

#define LLDP_MOD_8021QAZ	((OUI_IEEE_8021 << 8) | IEEE8021QAZ_ETSCFG_TLV)

#define MAX_USER_PRIORITIES	8
#define MAX_TCS			8
#define BW_PERCENT		100

/* maximum number of application entries allowed to be
 * configured in an application TLV.
 */
#define MAX_APP_ENTRIES		32

#define DEFAULT_SUBTYPE		0
#define INIT_IEEE8021QAZ_OUI	{0x00, 0x80, 0xc2}

/* IEEE8021QAZ TLV Definitions */
#define IEEE8021QAZ_ETSCFG_TLV	9
#define IEEE8021QAZ_ETSREC_TLV	10
#define IEEE8021QAZ_PFC_TLV	11
#define IEEE8021QAZ_APP_TLV	12

#define IEEE8021QAZ_SETTING	"ieee8021qaz"
#define TLV_HEADER_LENGTH	2

/* Received TLV types */
#define RCVD_IEEE8021QAZ_TLV_ETSCFG	0x0001
#define RCVD_IEEE8021QAZ_TLV_ETSREC	0x0002
#define RCVD_IEEE8021QAZ_TLV_PFC	0x0004
#define RCVD_IEEE8021QAZ_TLV_APP	0x0008
#define RCVD_LLDP_IEEE8021QAZ_TLV	0x0200

/* Duplicate TLV types */
#define DUP_IEEE8021QAZ_TLV_ETSCFG	0x0001
#define DUP_IEEE8021QAZ_TLV_ETSREC	0x0002
#define DUP_IEEE8021QAZ_TLV_PFC		0x0004
#define DUP_IEEE8021QAZ_TLV_APP		0x0008

/* Transmission selection algorithm identifiers */
#define IEEE8021Q_TSA_STRICT	0x0
#define IEEE8021Q_TSA_CBSHAPER	0x1
#define IEEE8021Q_TSA_ETS	0x2
#define IEEE8021Q_TSA_VENDOR	0xFF

/* Flags */
#define IEEE8021QAZ_SET_FLAGS(_FlagsVar, _BitsToSet)	\
			((_FlagsVar) = (_FlagsVar) | (_BitsToSet))

#define IEEE8021QAZ_TEST_FLAGS(_FlagsVar, _Mask, _BitsToCheck)	\
			(((_FlagsVar) & (_Mask)) == (_BitsToCheck))

/* APP internal state */
#define IEEE_APP_SET 0
#define IEEE_APP_DEL 1
#define IEEE_APP_DONE 2

/* ETSCFG WCRT field's Shift values */
#define ETS_WILLING_SHIFT	7
#define ETS_CBS_SHIFT		6

enum state {
	INIT,
	RX_RECOMMEND
};


/* Packed TLVs */
struct ieee8021qaz_tlv_etscfg {
	u8 oui[OUI_SIZE];
	u8 subtype;
	u8 wcrt;		/* Willing-Cbs-Reserved-maxTc fields */
	u32 prio_map;		/* Priority Assignment Table */
	u8 tc_bw[MAX_TCS];	/* TC Bandwidth Table */
	u8 tsa_map[MAX_TCS];	/* Transmission Selection Algorithm Table */
} __attribute__ ((__packed__));

struct ieee8021qaz_tlv_etsrec {
	u8 oui[OUI_SIZE];
	u8 subtype;
	u8 reserved;
	u32 prio_map;		/* Priority Assignment Table */
	u8 tc_bw[MAX_TCS];	/* TC Bandwidth Table */
	u8 tsa_map[MAX_TCS];	/* Transmission Selection Algorithm Table */
} __attribute__ ((__packed__));

struct ieee8021qaz_tlv_pfc {
	u8 oui[OUI_SIZE];
	u8 subtype;
	u8 wmrc;		/* Willing-Mbc-Reserved-pfcCap fields */
	u8 pfc_enable;		/* PFC Enable */
} __attribute__ ((__packed__));

struct ieee8021qaz_tlv_app {
	u8 oui[OUI_SIZE];
	u8 subtype;
	u8 reserved;
} __attribute__ ((__packed__));

struct app_prio {
	u8 prs;			/* Priority-Reserved-Selection fields */
	u16 pid;
} __attribute__ ((__packed__));

/* ETS Configuration Object */
struct etscfg_obj {
	bool willing;
	bool cbs;
	u8 max_tcs;
	u32 prio_map;
	u8 tc_bw[MAX_TCS];
	u8 tsa_map[MAX_TCS];
};

/* ETS Recommendation Object */
struct etsrec_obj {
	u32 prio_map;
	u8 tc_bw[MAX_TCS];
	u8 tsa_map[MAX_TCS];
};

/* PFC Object */
struct pfc_obj {
	/* DCBX PFC Params */
	bool willing;
	bool mbc;
	u8 pfc_cap;
	u8 pfc_enable;
	u32 delay;
};

/* Application Objects */
struct app_obj {
	struct dcb_app app;
	bool peer;
	int hw;
	LIST_ENTRY(app_obj) entry;
};

/* @oper_param - 0: local_params, 1: remote_params
 * @remote_param - 0: NULL */
struct ets_attrib {
	bool pending;
	bool current_state;
	struct etscfg_obj *cfgl;
	struct etsrec_obj *recl;
	struct etscfg_obj *cfgr;
	struct etsrec_obj *recr;
};

struct pfc_attrib {
	bool pending;
	bool current_state;
	struct pfc_obj local;
	struct pfc_obj remote;
	bool remote_param;
};

struct ieee8021qaz_unpkd_tlvs {
	struct unpacked_tlv *ieee8021qaz;
	struct unpacked_tlv *etscfg;
	struct unpacked_tlv *etsrec;
	struct unpacked_tlv *pfc;
	struct unpacked_tlv *app;
};

struct ieee8021qaz_tlvs {
	bool active;
	bool pending;
	u16 ieee8021qazdu;
	u8 local_mac[ETH_ALEN];
	u8 remote_mac[ETH_ALEN];
	char ifname[IFNAMSIZ];
	struct ieee8021qaz_unpkd_tlvs *rx;
	struct ets_attrib *ets;
	struct pfc_attrib *pfc;
	LIST_HEAD(app_tlv_head, app_obj) app_head;
	struct port *port;
	LIST_ENTRY(ieee8021qaz_tlvs) entry;
};

struct ieee8021qaz_user_data {
	LIST_HEAD(ieee8021qaz_head, ieee8021qaz_tlvs) head;
};

int ieee8021qaz_mod_app(struct app_tlv_head *head, int peer,
			u8 prio, u8 sel, u16 proto, u32 ops);
int ieee8021qaz_app_sethw(char *ifname, struct app_tlv_head *head);

inline int get_prio_map(u32 prio_map, int tc);
inline void set_prio_map(u32 *prio_map, u8 prio, int tc);

struct ieee8021qaz_tlvs *ieee8021qaz_data(const char *);

int ieee8021qaz_tlvs_rxed(const char *ifname);
int ieee8021qaz_check_active(const char *ifname);

struct lldp_module *ieee8021qaz_register(void);
void ieee8021qaz_unregister(struct lldp_module *mod);
struct packed_tlv *ieee8021qaz_gettlv(struct port *port, struct lldp_agent *);
int ieee8021qaz_rchange(struct port *port, struct lldp_agent *,
			struct unpacked_tlv *tlv);
void ieee8021qaz_ifup(char *ifname, struct lldp_agent *);
void ieee8021qaz_ifdown(char *ifname, struct lldp_agent *);
u8 ieee8021qaz_mibDeleteObject(struct port *port, struct lldp_agent *);
inline int ieee8021qaz_clif_cmd(void *data, struct sockaddr_un *from,
				socklen_t fromlen, char *ibuf, int ilen,
				char *rbuf);
int ieee8021qaz_check_operstate(void);
int get_dcbx_hw(const char *ifname, __u8 *dcbx);

#endif	/* _LLDP_8021QAZ_H */
