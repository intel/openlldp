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

#ifndef _LLDP_TLV_H
#define _LLDP_TLV_H

#include "lldp.h"
#include "lldp/ports.h"

#define ADDR2TLVSTR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define TLVSTR "%02x%02x%02x%02x%02x%02x"   /* Localization OK */

#define TLV_OK 0
#define TLV_ERR 1
#define SUBTYPE_INVALID 2

/* Bit Mappers */
#define BIT0 0x01
#define BIT1 0x02
#define BIT2 0x04
#define BIT3 0x08
#define BIT4 0x10
#define BIT5 0x20
#define BIT6 0x40
#define BIT7 0x80

#define TYPE_0   0
#define TYPE_1   1
#define TYPE_2   2
#define TYPE_3   3
#define TYPE_4   4
#define TYPE_5   5
#define TYPE_6   6
#define TYPE_7   7
#define TYPE_8   8
#define TYPE_127 127

/* Received TLV types */
#define RCVD_LLDP_TLV_TYPE0         0x0001
#define RCVD_LLDP_TLV_TYPE1         0x0002
#define RCVD_LLDP_TLV_TYPE2         0x0004
#define RCVD_LLDP_TLV_TYPE3         0x0008
#define RCVD_LLDP_TLV_TYPE4         0x0010
#define RCVD_LLDP_TLV_TYPE5         0x0020
#define RCVD_LLDP_TLV_TYPE6         0x0040
#define RCVD_LLDP_TLV_TYPE7         0x0080
#define RCVD_LLDP_TLV_TYPE8         0x0100


/* Protocol EtherTypes */
#define PROTO_ID_FCOE                  0x0689 /* network byte order */
#define PROTO_ID_ISCSI                 0xBC0C /* network byte order, 3260 dec */
#define PROTO_ID_FIP                   0x1489 /* network byte order */

/* Protocol Selector Field */
#define PROTO_ID_L2_ETH_TYPE           0x00
#define PROTO_ID_SOCK_NUM              0x01
#define PROTO_ID_RESERVED1             0x02
#define PROTO_ID_RESERVED2             0x03

#define PROTO_ID_OUI_MASK              0xFC
#define PROTO_ID_SF_TYPE               0x03

enum {
	CURRENT_PEER,
	LAST_PEER
};

struct packed_tlv {
	u16 size;     /* Of the entire tlv block */
	u8 *tlv;      /* tlv block */
};

struct unpacked_tlv {
	u8  type;
	u16 length;
	u8  *info;
};

struct packed_tlv *pack_tlv(struct unpacked_tlv *tlv);
struct unpacked_tlv *unpack_tlv(struct packed_tlv *tlv);
int pack_tlv_after(struct unpacked_tlv *, struct packed_tlv *, int);

struct unpacked_tlv *free_unpkd_tlv(struct unpacked_tlv *tlv);
struct packed_tlv *free_pkd_tlv(struct packed_tlv *tlv);
struct unpacked_tlv *create_tlv(void);
struct packed_tlv *create_ptlv(void);
struct unpacked_tlv *bld_end_tlv(void);
struct packed_tlv *pack_end_tlv(void);

int tlv_ok(struct unpacked_tlv *tlv);

#define FREE_UNPKD_TLV(d, f) \
{ \
	if ((d)->f) \
		(d)->f = free_unpkd_tlv((d)->f); \
}

#define FREE_PKD_TLV(d, f) \
{ \
	if ((d)->f) \
		(d)->f = free_pkd_tlv((d)->f); \
}

#define PACK_TLV_AFTER(t, p, l, g) 		\
	if (pack_tlv_after((t), (p), (l))) {	\
		fprintf(stderr, "### failed to pack " #t "\n");	\
		goto g;				\
	}
/* TLVID is oui << 8 | subtype */
#define TLVID(oui, sub)		((((oui) << 8) & 0xfffff00) | ((sub) & 0xff))
#define TLVID_NOUI(sub)		TLVID(0, (sub))
#define TLVID_DCBX(sub)		TLVID(OUI_IEEE_DCBX, (sub))
#define TLVID_8021(sub)		TLVID(OUI_IEEE_8021, (sub))
#define TLVID_8023(sub)		TLVID(OUI_IEEE_8023, (sub))
#define TLVID_MED(sub)		TLVID(OUI_TIA_TR41, (sub))
#define TLVID_8021Qbg(sub)	TLVID(OUI_IEEE_8021Qbg, (sub))

/* the size in bytes needed for a packed tlv from unpacked tlv */
#define TLVSIZE(t) ((t) ? (2 + (t)->length) : 0)

#endif /* TLVS_H */
