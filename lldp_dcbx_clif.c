/*******************************************************************************

  LLDP Agent Daemon (LLDPAD) Software
  Copyright(c) 2007-2010 Intel Corporation.

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

#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/un.h>
#include <sys/stat.h>
#include "lldp_mod.h"
#include "lldptool.h"
#include "clif_msgs.h"
#include "lldp.h"
#include "lldp_dcbx.h"
#include "lldp_dcbx_clif.h"
#include "tlv_dcbx.h"

void print_dcbx_v1(u16, char *info);
void print_dcbx_v2(u16, char *info);
u32 dcbx_lookup_tlv_name(char *tlvid_str);
int dcbx_print_help();

static const struct lldp_mod_ops dcbx_ops_clif = {
	.lldp_mod_register 	= dcbx_cli_register,
	.lldp_mod_unregister 	= dcbx_cli_unregister,
	.print_tlv		= dcbx_print_tlv,
	.lookup_tlv_name	= dcbx_lookup_tlv_name,
	.print_help		= dcbx_print_help,
};

struct type_name_info dcbx_tlv_names[] = {
	{	.type = (OUI_CEE_DCBX << 8) | 1,
		.name = "CIN DCBX TLV", .key = "CIN-DCBX",
		.print_info = print_dcbx_v1, },
	{	.type = (OUI_CEE_DCBX << 8) | 2,
		.name = "CEE DCBX TLV", .key = "CEE-DCBX",
		.print_info = print_dcbx_v2, },
	{	.type = INVALID_TLVID, }
};

int dcbx_print_help()
{
	struct type_name_info *tn = &dcbx_tlv_names[0];

	while (tn->type != INVALID_TLVID) {
		if (tn->key && strlen(tn->key) && tn->name) {
			printf("   %s", tn->key);
			if (strlen(tn->key)+3 < 8)
				printf("\t");
			printf("\t: %s\n", tn->name);
		}
		tn++;
	}
	
	return 0;
}

struct lldp_module *dcbx_cli_register(void)
{
	struct lldp_module *mod;

	mod = malloc(sizeof(*mod));
	if (!mod) {
		fprintf(stderr, "failed to malloc module data\n");
		goto out_err;
	}
 	mod->id = LLDP_MOD_DCBX;
	mod->ops = &dcbx_ops_clif;

	return mod;
out_err:
	return NULL;
}

void dcbx_cli_unregister(struct lldp_module *mod)
{
	free(mod);
}

static void print_dcbx_feature_header(char *info, int offset, u8 *subtype)
{
	u8 flags;
	u16 op_version, max_version;

	hexstr2bin(info+offset, (u8 *)&op_version, sizeof(op_version));
	op_version = ntohs(op_version);
	hexstr2bin(info+offset+2, (u8 *)&max_version, sizeof(max_version));
	max_version = ntohs(max_version);

	hexstr2bin(info+offset+4, (u8 *)&flags, sizeof(flags));
	printf("\t  %sEnabled, %sWilling, %sError\n",
		(flags & 0x80) ? "" : "Not ",
		(flags & 0x40) ? "" : "Not ",
		(flags & 0x20) ? "" : "No ");
	hexstr2bin(info+offset+6, (u8 *)subtype, sizeof(*subtype));
}

void print_dcbx_v1(u16 len, char *info)
{
	int offset = 0;
	u16 tlvtype;
	u16 tlvlen;
	u8 bwgid;
	u8 bwgidmap[8];
	u8 bwgpctmap[8];
	u8 strictmap[8];
	u8 bwgpct, bwpct;
	u8 pfcmap;
	u8 op_version, max_version;
	u32 seqno, ackno;
	u8 subtype;
	int i, j, cnt;
	int print_comma;
	int print_bwgid;
	u8 app_up_map;
	u8 llink;

	while (offset < 2*len) {
		hexstr2bin(info+offset, (u8 *)&tlvtype, sizeof(tlvtype));
		tlvtype = ntohs(tlvtype);
		tlvlen = tlvtype & 0x1FF;
		tlvtype >>= 9;

		offset += 4;

		switch(tlvtype) {
		case DCB_CONTROL_TLV:
			hexstr2bin(info+offset, (u8 *)&op_version,
				   sizeof(op_version));
			op_version = ntohs(op_version);
			hexstr2bin(info+offset+2, (u8 *)&max_version,
				   sizeof(max_version));
			max_version = ntohs(max_version);
			printf("Control TLV:\n");

			hexstr2bin(info+offset+4, (u8 *)&seqno, sizeof(seqno));
			seqno = ntohl(seqno);
			hexstr2bin(info+offset+12, (u8 *)&ackno, sizeof(ackno));
			ackno = ntohl(ackno);
			printf("\t  SeqNo: %d, AckNo: %d\n", seqno, ackno);
			break;
		case DCB_PRIORITY_GROUPS_TLV:
			printf("\tPriority Groups TLV:\n");
			print_dcbx_feature_header(info, offset, &subtype);

			printf("\t  BWG Percentages: ");
			for (i = 0; i < 8; i++) {
				hexstr2bin(info+offset+8+i*2, (u8 *)&bwpct,
					   sizeof(bwpct));
				printf("%d:%d%%%s", i, bwpct,
					(i == 7) ? "\n" : " ");
			}
			printf("\t  BWG Priorities: ");
			for (i = 0; i < 8; i++) {
				hexstr2bin(info+offset+8+16+4*i, (u8 *)&bwgid,
					   sizeof(bwgid));
				hexstr2bin(info+offset+8+16+4*i + 2,
					  (u8 *)&bwgpct, sizeof(bwgpct));
				bwgidmap[i] = (bwgid & 0xe0) >> 5;
				strictmap[i] = (bwgid & 0x18) >> 3;
				bwgpctmap[i] = bwgpct;
			}

			cnt = 0;
			for (i = 0; i < 8; i++) {
				print_bwgid = 1;
				print_comma = 0;
				for (j = 0; j < 8; j++) {
					if (bwgidmap[j] == i) {
						if (print_bwgid)
							printf(" %d:[", i);
						printf("%s%d%s-%d%%",
							(print_comma)?", ":"",
							j,
							(strictmap[j] == 1) ?
							"(ls)" : (
							(strictmap[j] == 2) ?
							"(gs)" : ""),
							bwgpctmap[j]);
						print_bwgid = 0;
						print_comma = 1;
						if (++cnt == 4) {
							if (!print_bwgid)
								printf("]");
							printf("\n\t\t\t  ");
							print_bwgid = 1;
							print_comma = 0;
						}
					}
				}
				if (!print_bwgid)
					printf("]");
			}
			printf("\n");
			break;
		case DCB_PRIORITY_FLOW_CONTROL_TLV:
			printf("\tPriority Flow Control TLV:\n");
			print_dcbx_feature_header(info, offset, &subtype);

			hexstr2bin(info+offset+8, (u8 *)&pfcmap,
				   sizeof(pfcmap));
			printf("\t  PFC enabled priorities: ");
			print_comma = 0;
			for (i = 0; i < 8; i++) {
				if ((1<<i) & pfcmap) {
					printf("%s%d", (print_comma)?", ":"",
						i);
					print_comma = 1;
				}
			}
			if (!print_comma)
				printf("none");
			printf("\n");
			break;
		case DCB_APPLICATION_TLV:
			printf("\tApplication TLV:\n");
			print_dcbx_feature_header(info, offset, &subtype);

			hexstr2bin(info+offset+8, (u8 *)&app_up_map,
				   sizeof(app_up_map));

			if (subtype == 0) /* FCoE */
				printf("\t  FCoE ");
			else
				printf("\t  Subtype: %d ", subtype);

			printf("Priority Map: 0x%02x\n", app_up_map);

			break;
		case DCB_LLINK_TLV:
			hexstr2bin(info+offset+6, (u8 *)&subtype,
				   sizeof(subtype));
			if (subtype == 0)
				printf("\tFCoE Logical Link TLV:\n");
			else if (subtype == 1)
				printf("\tLAN Logical Link TLV:\n");
			print_dcbx_feature_header(info, offset, &subtype);

			hexstr2bin(info+offset+8, (u8 *)&llink, sizeof(llink));
			printf("\t  Link is %s\n", (llink & 0x80)?"up":"down");
			break;
		case DCB_BCN_TLV:
			printf("\tUnhandled DCBX BCN TLV\n");
			break;
		default:
			printf("\tUnknown DCBX sub-TLV %d: %*.*s\n",
			       tlvtype, 2*tlvlen, 2*tlvlen, info+offset);
			break;
		}

		offset += 2*tlvlen;
	}
}

void print_dcbx_v2(u16 len, char *info)
{
	int offset = 0;
	int suboff;
	u16 tlvtype;
	u16 tlvlen;
	u8 pgid;
	u8 pgidmap[8];
	u8 pgpct;
	u8 pfcmap;
	u8 numtcs;
	u8 op_version, max_version;
	u32 seqno, ackno;
	u8 subtype;
	int i, j;
	int print_comma;
	int print_pgid;
	u16 app_protoid;
	u8 oui_up8;
	u16 oui_low16;
	u8 app_up_map;
	u8 llink;

	while (offset < 2*len) {
		hexstr2bin(info+offset, (u8 *)&tlvtype, sizeof(tlvtype));
		tlvtype = ntohs(tlvtype);
		tlvlen = tlvtype & 0x1FF;
		tlvtype >>= 9;

		offset += 4;

		switch(tlvtype) {
		case DCB_CONTROL_TLV2:
			hexstr2bin(info+offset, (u8 *)&op_version,
				   sizeof(op_version));
			op_version = ntohs(op_version);
			hexstr2bin(info+offset+2, (u8 *)&max_version,
				   sizeof(max_version));
			max_version = ntohs(max_version);
			printf("Control TLV:\n");

			hexstr2bin(info+offset+4, (u8 *)&seqno, sizeof(seqno));
			seqno = ntohl(seqno);
			hexstr2bin(info+offset+12, (u8 *)&ackno, sizeof(ackno));
			ackno = ntohl(ackno);
			printf("\t  SeqNo: %d, AckNo: %d\n", seqno, ackno);
			break;
		case DCB_PRIORITY_GROUPS_TLV2:
			printf("\tPriority Groups TLV:\n");
			print_dcbx_feature_header(info, offset, &subtype);

			printf("\t  PGID Priorities: ");
			for (i = 0; i < 4; i++) {
				hexstr2bin(info+offset + 8 + 2*i, (u8 *)&pgid,
					   sizeof(pgid));
				pgidmap[2*i] = (pgid & 0xf0) >> 4;
				pgidmap[2*i+1] = (pgid & 0x0f);
			}


			for (i = 0; i < 16; i++) {
				print_pgid = 1;
				print_comma = 0;
				for (j = 0; j < 8; j++) {
					if (pgidmap[j] == i) {
						if (print_pgid)
							printf(" %d:[", i);
						printf("%s%d",
							(print_comma)?",":"",
							j);
						print_pgid = 0;
						print_comma = 1;
					}
				}
				if (!print_pgid)
					printf("]");
			}
			printf("\n\t  PGID Percentages: ");
			for (i = 0; i < 8; i++) {
				hexstr2bin(info+offset+8+8+i*2, (u8 *)&pgpct,
					   sizeof(pgpct));
				printf("%d:%d%%%s", i, pgpct,
					(i == 7) ? "\n" : " ");
			}
			hexstr2bin(info+offset+8+8+16, (u8 *)&numtcs,
				   sizeof(numtcs));
			printf("\t  Number of TC's supported: %d\n", numtcs);
			break;
		case DCB_PRIORITY_FLOW_CONTROL_TLV2:
			printf("\tPriority Flow Control TLV:\n");
			print_dcbx_feature_header(info, offset, &subtype);

			hexstr2bin(info+offset+8, (u8 *)&pfcmap,
				   sizeof(pfcmap));
			hexstr2bin(info+offset+10, (u8 *)&numtcs,
				   sizeof(numtcs));
			printf("\t  PFC enabled priorities: ");
			print_comma = 0;
			for (i = 0; i < 8; i++) {
				if ((1<<i) & pfcmap) {
					printf("%s%d", (print_comma)?", ":"",
						i);
					print_comma = 1;
				}
			}
			if (!print_comma)
				printf("none");
			printf("\n");
			printf("\t  Number of TC's supported: %d\n", numtcs);
			break;
		case DCB_APPLICATION_TLV2:
			printf("\tApplication TLV:\n");
			print_dcbx_feature_header(info, offset, &subtype);

			suboff = 8;
			while (suboff < 2*tlvlen) {
				hexstr2bin(info+offset+suboff,
					   (u8 *)&app_protoid,
					   sizeof(app_protoid));
				app_protoid = ntohs(app_protoid);
				hexstr2bin(info+offset+suboff+4,
					   (u8 *)&oui_up8,
					   sizeof(oui_up8));
				hexstr2bin(info+offset+suboff+6,
					   (u8 *)&oui_low16,
					   sizeof(oui_low16));
				oui_low16 = ntohs(oui_low16);
				hexstr2bin(info+offset+suboff+10,
					   (u8 *)&app_up_map,
					   sizeof(app_up_map));

				if (((oui_up8 & 0xfc) ==
				   ((OUI_INTEL_CORP>>16) & 0x0fc)) &&
				    (oui_low16 == (OUI_INTEL_CORP & 0x0ffff))) {
					if ((oui_up8 & 0x03) == 0) {
						printf("\t  Ethertype: 0x%04x",
							app_protoid);
					} else if ((oui_up8 & 0x03) == 1) {
						printf("\t  TCP/UDP Port: 0x%04x",
							app_protoid);
					} else {
						printf("\t  Reserved: 0x%04x",
							app_protoid);
					}
				} else {
					printf("\t  OUI: 0x%02x%04x",
						oui_up8 & 0xfc, oui_low16);
					printf(", Selector: %d",
						oui_up8 & 0x03);
					printf(", Protocol ID: 0x%04x",
						app_protoid);
				}

				printf(", Priority Map: 0x%02x\n",
					app_up_map);
				suboff += 12;
			}
			break;
		case DCB_LLINK_TLV:
			hexstr2bin(info+offset+6, (u8 *)&subtype,
				   sizeof(subtype));
			if (subtype == 0)
				printf("\tFCoE Logical Link TLV:\n");
			else if (subtype == 1)
				printf("\tLAN Logical Link TLV:\n");
			print_dcbx_feature_header(info, offset, &subtype);

			hexstr2bin(info+offset+8, (u8 *)&llink, sizeof(llink));
			printf("\t  Link is %s\n",
			       (llink & 0x80) ? "up" : "down");
			break;
		default:
			printf("\tUnknown DCBX sub-TLV %d: %*.*s\n",
			       tlvtype, 2*tlvlen, 2*tlvlen, info+offset);
			break;
		}

		offset += 2*tlvlen;
	}
}

/* return 1: if it printed the TLV
 *        0: if it did not
 */
int dcbx_print_tlv(u32 tlvid, u16 len, char *info)
{
	struct type_name_info *tn = &dcbx_tlv_names[0];

	while (tn->type != INVALID_TLVID) {
		if (tlvid == tn->type) {
			printf("%s\n", tn->name);
			if (tn->print_info) {
				printf("\t");
				tn->print_info(len-4, info);
			}
			return 1;
		}
		tn++;
	}
	
	return 0;
}

u32 dcbx_lookup_tlv_name(char *tlvid_str)
{
	struct type_name_info *tn = &dcbx_tlv_names[0];

	while (tn->type != INVALID_TLVID) {
		if (!strcasecmp(tn->key, tlvid_str))
			return tn->type;
		tn++;
	}
	return INVALID_TLVID;
}
