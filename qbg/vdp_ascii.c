/******************************************************************************

  Implementation of VDP 22 (ratified standard) according to IEEE 802.1Qbg
  (c) Copyright IBM Corp. 2014

  Author(s): Thomas Richter <tmricht@linux.vnet.ibm.com>

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
 * Convertion function for data exchange between lldptool and lldpad.
 * Get an ascii string and convert it to a vdpnl_vsi structure.
 * Get a vdpnl_vsi structure and convert it to an ascii string.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>

#include <net/if.h>

#include "qbg_vdp22def.h"
#include "qbg_vdp22.h"
#include "qbg_vdpnl.h"
#include "qbg_utils.h"

/*
 * Check if it is a UUID and consists  of hexadecimal digits and dashes only.
 * If so convert it to UUID.
 */
int vdp_str2uuid(unsigned char *to, char *buffer, size_t max)
{
	unsigned int i, j = 0;
	size_t buffer_len = strlen(buffer);

	if (strspn(buffer, "01234567890AaBbCcDdEeFf-") != buffer_len)
		return -1;
	memset(to, 0, max);
	for (i = 0; i < buffer_len && j < max; i++) {
		if (buffer[i] == '-')
			continue;
		if (sscanf(&buffer[i], "%02hhx", &to[j]) == 1) {
			i++;
			j++;
		}
	}
	if (i < buffer_len)
		return -2;		/* Not enough space */
	return 0;
}

/*
 * Convert a 16byte uuid to string. Insert dashes for better readability.
 */
int vdp_uuid2str(const unsigned char *p, char *dst, size_t size)
{
	if (dst && size > VDP_UUID_STRLEN) {
		snprintf(dst, size, "%02x%02x%02x%02x-%02x%02x-%02x%02x"
			 "-%02x%02x-%02x%02x%02x%02x%02x%02x",
			 p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
			 p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
		return 0;
	}
	return -1;
}

/*
 * Return true if string is a number between min and max.
 */
static bool getnumber(char *s, unsigned int min, unsigned int max,
		      unsigned int *no)
{
	char *myend;

	*no = strtol(s, &myend, 0);
	if (s && *myend == '\0' && min <= *no && *no <= max)
		return true;
	return false;
}

/*
 * Read filter information data. The format is an ascii string:
 * filter-data		filter-format
 * vlan			1
 * vlan-mac		2
 * vlan--group		3
 * vlan-mac-group	4
 */
static bool getfid(struct vdpnl_vsi *p, char *value, long idx)
{
	char *delim2 = 0, *delim = strchr(value, '-');
	unsigned int vlan, gpid = 0;
	int fif, i, have_mac = 1, have_gpid = 1;
	unsigned char x[ETH_ALEN];

	memset(x, 0, sizeof(x));
	if (!delim)		/* No dash --> no mac, no group */
		have_gpid = have_mac = 0;
	else {
		*delim = '\0';
		delim2 = strchr(delim + 1, '-');
		if (!delim2)	/* No 2nd dash --> have mac but no group */
			have_gpid = 0;
		else {		/* 2 dashes --> check for mac */
			*delim2 = '\0';
			if (delim + 1 == delim2)
				/* -- means vlan and group without mac */
				have_mac = 0;
		}
	}
	if (!getnumber(value, 0, 0xffff, &vlan))
		return false;
	fif = VDP22_FFMT_VID;
	if (have_mac) {
		i = sscanf(delim + 1,
			   "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
			   &x[0], &x[1], &x[2], &x[3], &x[4], &x[5]);
		if (i != ETH_ALEN)
			return false;
		fif = VDP22_FFMT_MACVID;
	}

	/* Check for optional group identifier */
	if (have_gpid && *(delim2 + 1)) {
		if (!getnumber(delim2 + 1, 1, ~0U, &gpid))
			return false;
		fif += 2;
	}

	/* We already have filter information data, filter format must match */
	if (p->filter_fmt && p->filter_fmt != fif)
		return false;
	p->filter_fmt = fif;

	/* Check if this mac is already in our list */
	for (i = 0; have_mac && i < p->macsz; ++i) {
		if (!memcmp(x, p->maclist[i].mac, sizeof(p->maclist[i].mac)))
			return false;
	}

	/* Append to end of list */
	p->maclist[idx].vlan = vdp22_get_vlanid(vlan);
	p->maclist[idx].qos = vdp22_get_qos(vlan);
	p->maclist[idx].gpid = gpid;
	memcpy(p->maclist[idx].mac, x, sizeof(p->maclist[0].mac));
	return true;
}

/*
 * Read manager identifier (max 16 bytes). Check if it is a UUID and consists
 * of hexadecimal digits only. If so convert it to UUID.
 */
static bool getmgr2id(struct vdpnl_vsi *p, char *s)
{
	bool is_good;
	size_t cnt = 0, i, slen = strlen(s);
	char *s_old = s;

	if (vdp_str2uuid(p->vsi_mgrid2, s, sizeof(p->vsi_mgrid2)) == 0)
		return true;
	/* Check for alphanumeric string */
	for (i = 0; i < slen; ++i, ++s)
		if (isalnum(*s))
			++cnt;
	is_good = cnt == slen && cnt < sizeof(p->vsi_mgrid2);
	if (is_good)
		memcpy(p->vsi_mgrid2, s_old, cnt);
	return is_good;
}

/*
 * Read VSI VM hints.
 */
static bool gethints(struct vdpnl_vsi *p, char *s)
{
	if (!strcasecmp(s, "to"))
		p->hints = VDP22_MIGTO;
	else if (!strcasecmp(s, "from"))
		p->hints = VDP22_MIGFROM;
	else if (!strcasecmp(s, "none") || !strcasecmp(s, "-"))
		p->hints = 0;
	else
		return false;
	return true;
}

/*
 * Read VSI association mode. If can be followed by an error code in brackets.
 * For vdp22 protocol the allowed words are assoc, preassoc, preassoc-rr and
 * deassoc.
 * For vdp draft 0.2 the allowed commands are 0, 1, 2 and 3.
 */
static bool getmode(struct vdpnl_vsi *p, char *s)
{
	char *myend, *bracket = strchr(s, '[');
	int no;

	if (strlen(s) == 1) {
		switch (*s) {
		case '0':	p->request = VDP22_PREASSOC;
				break;
		case '1':	p->request = VDP22_PREASSOC_WITH_RR;
				break;
		case '2':	p->request = VDP22_ASSOC;
				break;
		case '3':	p->request = VDP22_DEASSOC;
				break;
		default:	return false;
		}
		p->request -= 1;
		p->nl_version = vdpnl_nlf1;
		return true;
	}

	if (bracket) {
		*bracket = '\0';
		no = strtol(bracket + 1, &myend, 0);
		if (*myend != ']')
			return false;
		p->response = no;
	}
	if (!strcasecmp(s, "assoc"))
		p->request = VDP22_ASSOC;
	else if (!strcasecmp(s, "preassoc"))
		p->request = VDP22_PREASSOC;
	else if (!strcasecmp(s, "preassoc-rr"))
		p->request = VDP22_PREASSOC_WITH_RR;
	else if (!strcasecmp(s, "deassoc"))
		p->request = VDP22_DEASSOC;
	else
		return false;
	p->nl_version = vdpnl_nlf2;
	return true;
}

/*
 * Parse the mode parameter to create/change an VSI assoication.
 * The format is a comma separated list of tokens:
 * cmd,mgrid,typeid,typeidversion,vsiid,hints,fid[,fid,fid,...]
 * with
 * cmd := "assoc" | "deassoc" | "preassoc" | "preassoc-rr"
 * mgrid :=  less or equal to 16 byte alphanumeric characters
 *		| UUID (with dashes in between)
 * typeid := number in range of 1 - 2^24 -1
 * typeidversion:= number in range of 1 - 255
 * vsiid := UUID (with dashes in between)
 * hints := varies between input (command) and output (event message)
 *          on input --> dash (-) | "none" | "from" | "to"
 *          on output --> response (number between 0..255)
 * fid := vlan
 *	| vlan-mac
 *	| vlan--group
 *	| vlan-mac-group
 * vlan := number in range of 1..2^16 -1
 * group := number in range of 1..2^32 - 1
 * mac := xx:xx:xx:xx:xx:xx
 */

static int str2vdpnl(char *argvalue, struct vdpnl_vsi *vsi)
{
	int rc = -ENOMEM;
	unsigned int no;
	unsigned short idx;
	char *cmdstring, *token;

	cmdstring = strdup(argvalue);
	if (!cmdstring)
		goto out_free;
	rc = -EINVAL;
	/* 1st field is VSI command */
	token = strtok(cmdstring, ",");
	if (!token || !getmode(vsi, token))
		goto out_free;

	/* 2nd field is VSI Manager Identifer (16 bytes maximum) */
	token = strtok(NULL, ",");
	if (!token || !getmgr2id(vsi, token))
		goto out_free;

	/* 3rd field is type identifier */
	token = strtok(NULL, ",");
	if (!token || !getnumber(token, 0, 0xffffff, &no))
		goto out_free;
	vsi->vsi_typeid = no;

	/* 4th field is type version identifier */
	token = strtok(NULL, ",");
	if (!token || !getnumber(token, 0, 0xff, &no))
		goto out_free;
	vsi->vsi_typeversion = no;

	/* 5th field is filter VSI UUID */
	token = strtok(NULL, ",");
	if (!token || vdp_str2uuid(vsi->vsi_uuid, token, sizeof(vsi->vsi_uuid)))
		goto out_free;
	vsi->vsi_idfmt = VDP22_ID_UUID;

	/* 6th field is migration hints */
	token = strtok(NULL, ",");
	if (!token || !gethints(vsi, token))
		goto out_free;

	/*
	 * 7th and remaining fields are filter information format data.
	 * All fields must have the same format. The first fid field determines
	 * the format.
	 */
	for (idx = 0, token = strtok(NULL, ","); token != NULL;
					++idx, token = strtok(NULL, ",")) {
		if (idx < vsi->macsz && !getfid(vsi, token, idx))
			goto out_free;
	}

	/* Return error if no filter information provided */
	if (idx)
		rc = 0;
out_free:
	free(cmdstring);
	return rc;
}

/*
 * Fill the vdpnl_vsi structure from the string.
 * Allocate the maclist. Must be free'ed by caller.
 */
int vdp_str2vdpnl(char *argvalue, struct vdpnl_vsi *vsi, char *ifname)
{
	if (ifname)
		strncpy(vsi->ifname, ifname, sizeof(vsi->ifname) - 1);
	return str2vdpnl(argvalue, vsi);
}

/*
 * Convert VSI profile into string. Use the same format as on input.
 * Return the number of bytes written into buffer. Return zero if not
 * enough buffer space. This ensures an entry is complete and no partial
 * entries are in buffer.
 */

/*
 * Check if snprintf() result completely fits into buffer.
 */
static char *check_and_update(size_t *total, size_t *length, char *s, int c)
{
	if (c < 0)
		return NULL;
	*total += c;
	if ((unsigned)c >= *length)
		return NULL;
	*length -= c;
	return s + c;
}

/*
 * Convert VSI association to string.
 */
static const char *mode2str(unsigned char x)
{
	if (x == VDP22_ASSOC)
		return "assoc";
	else if (x == VDP22_PREASSOC)
		return "preassoc";
	else if (x == VDP22_PREASSOC_WITH_RR)
		return "preassoc-rr";
	else if (x == VDP22_DEASSOC)
		return "deassoc";
	return "unknown";
}

/*
 * Convert filter information format into vlan[-mac][-group] string.
 * Return the number of bytes written into buffer. Return 0 if not
 * enough buffer space.
 */
static int fid2str(char *s, size_t length, int fif, struct vdpnl_mac *p)
{
	int c;
	size_t total = 0;

	c = snprintf(s, length, "%d", vdp22_set_qos(p->qos) |
		     vdp22_set_vlanid(p->vlan));
	s = check_and_update(&total, &length, s, c);
	if (!s)
		goto out;
	if (fif == VDP22_FFMT_MACVID || fif == VDP22_FFMT_GROUPMACVID) {
		c = snprintf(s, length, "-%02x:%02x:%02x:%02x:%02x:%02x",
			     p->mac[0], p->mac[1], p->mac[2], p->mac[3],
			     p->mac[4], p->mac[5]);
		s = check_and_update(&total, &length, s, c);
		if (!s)
			goto out;
	}
	if (fif == VDP22_FFMT_GROUPVID || fif == VDP22_FFMT_GROUPMACVID) {
		c = snprintf(s, length, "-%ld", p->gpid);
		s = check_and_update(&total, &length, s, c);
		if (!s)
			goto out;
	}
out:
	return s ? total : 0;
}

/*
 * Mgrid can be a one byte number ranging from 0..255 or a 16byte long
 * identifier.
 */
static void mgrid2str(char *to, struct vdpnl_vsi *p, size_t to_len)
{
	int c;

	memset(to, 0, to_len);
	for (c = sizeof(p->vsi_mgrid2); c > 0; )
		if (p->vsi_mgrid2[--c])
			break;
	if (c)
		memcpy(to, p->vsi_mgrid2, sizeof(p->vsi_mgrid2));
	else
		snprintf(to, to_len, "%d", p->vsi_mgrid2[0]);
}

/*
 * Convert a vdpnl_vsi to string.
 */
int vdp_vdpnl2str(struct vdpnl_vsi *p, char *s, size_t length)
{
	int c, i;
	size_t total = 0;
	char instance[VDP_UUID_STRLEN + 2];

	mgrid2str(instance, p, sizeof(instance));
	c = snprintf(s, length, "%s,%s,%ld,%d,",
		     mode2str(p->request), instance, p->vsi_typeid,
		     p->vsi_typeversion);
	s = check_and_update(&total, &length, s, c);
	if (!s)
		goto out;

	vdp_uuid2str(p->vsi_uuid, instance, sizeof(instance));
	c = snprintf(s, length, "%s,%d,", instance, p->response);
	s = check_and_update(&total, &length, s, c);
	if (!s)
		goto out;

	/* Add Filter information data */
	for (i = 0; i < p->macsz; ++i) {
		c = fid2str(s, length, p->filter_fmt, &p->maclist[i]);
		s = check_and_update(&total, &length, s, c);
		if (!c)
			goto out;
		if (p->macsz > 1 && i < p->macsz - 1) {
			c = snprintf(s, length, ",");
			s = check_and_update(&total, &length, s, c);
			if (!s)
				goto out;
		}
	}
out:
	return s ? total : 0;
}
