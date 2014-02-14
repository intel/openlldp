/******************************************************************************

  Implementation of VDP according to IEEE 802.1Qbg
  (c) Copyright IBM Corp. 2012, 2013

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

******************************************************************************/

/*
 * Test Program for lldpad to respond to LLDP TLV with EVB DU. The program
 * behaves like a switch and sends out LLDP traffic with EVB DU. Only the
 * EVB DU varies.
 *
 * The EVB data to be sent is read from a configuration file. Data is send
 * once per second. The configuration file specifies the data to be send
 * for each transmission.
 *
 * Support for ECP and VDP protocol has been added. The support is very simple
 * and contains automatic acknowledgement with some delay and error response.
 */

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <time.h>

#include <net/if.h>
#include <netinet/in.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>

#define	MYDEBUG		0
#define	DIM(x)		(sizeof(x)/sizeof(x[0]))
#define ETH_P_LLDP	0x88cc
#define ETH_P_ECP	0x8940
#define MACSTR		"%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC2STR(a)	(a)[0] & 0xff, (a)[1] & 0xff, (a)[2] & 0xff, \
			(a)[3] & 0xff, (a)[4] & 0xff, (a)[5] & 0xff

#define	ECPMAXACK	20		/* Longest ECP ack delay */
#define	VDPMAXACK	30		/* Longest VDP ack delay */
#define ECP_HLEN	4		/* ECP protocol header length */

static char *progname;
static unsigned char eth_p_lldp[2] = { 0x88, 0xcc };
static unsigned char eth_p_ecp[2] = { ETH_P_ECP >> 8, ETH_P_ECP & 0xff };

static int verbose;
static char *tokens[1024];	/* Used to parse command line params */
static int myfd;		/* Raw socket for LLDP protocol */
static int ecpfd;		/* Raw socket for ECP protocol */
static int timerfd;		/* Time descriptor */
static unsigned char my_mac[ETH_ALEN];	/* My source MAC address */
static unsigned long duration = 120;	/* Time to run program in seconds */
static unsigned long timeout = 1;	/* Time to wait in select in seconds */
static unsigned long timeout_us = 0;	/* Time to wait in select in usecs */

enum pr_optype {		/* Protocol actions */
	ECP_ACK,		/* ECP acknowledgement delay */
	ECP_SEQNO,		/* ECP sequnece number */
	VDP_ACK,		/* VDP acknowledgement delay */
	VDP_ERROR,		/* VDP Error returned */
	CMD_LAST		/* Must be last */
};

struct pr_op {			/* Protocol command */
	enum pr_optype type;	/* Protocol to apply this command */
	unsigned long value;	/* Value */
	int enabled;		/* True if active */
};
static struct pr_op cmd_on[CMD_LAST];

struct lldpdu {			/* LLDP Data unit to send */
	unsigned char *data;
	struct lldpdu *next;
	unsigned short len;	/* No of bytes */
	unsigned char manda;	/* Mandatory in reply chain */
};

struct lldp {			/* LLDP DUs */
	unsigned long time;	/* Delta to send */
	unsigned char *dst;	/* Destination mac address */
	unsigned char *src;	/* Source mac address */
	unsigned char *ether;	/* Ethertype value */
	struct lldpdu *head;	/* Ptr to TLV data units */
	struct lldpdu *recv;	/* Ptr to expected receive TLV data units */
	struct lldp *next;	/* Ptr to sucessor */
	struct pr_op *opr;	/* Protocol operation */
};

unsigned long runtime;		/* Program run time in seconds */
static struct lldp *lldphead;	/* List of commands */
static struct lldp *er_ecp;	/* Expected replies ECP protocol */
static struct lldp *er_evb;	/* Expected replies EVB protocol */

struct ecphdr {			/* ECP header received */
	unsigned char version;	/* Version number */
	unsigned char op;	/* Operation REQ, ACK */
	unsigned short subtype;	/* Subtype */
	unsigned short seqno;	/* Sequence number */
};

struct vdphdr {			/* VDP header */
	unsigned char opr;	/* Operation requested */
	unsigned char status;	/* Status */
	unsigned long vsi_tyid;	/* VSI Type id */
	unsigned char vsi_tyv;	/* VSI Type version */
	unsigned char vsi_tyfm;	/* VSI Type id format */
	unsigned char vsi_uuid[16];	/* VSI UUID */
	unsigned char fil_info;	/* Filter info format */
};

/* Return ECP protocol acknowledgement delay and other settings */
static unsigned long ecp_inc_seqno(void)
{
	if (++cmd_on[ECP_SEQNO].value == 0)
		++cmd_on[ECP_SEQNO].value;
	return cmd_on[ECP_SEQNO].value;
}

static unsigned long ecp_ackdelay(void)
{
	return cmd_on[ECP_ACK].value;
}

static unsigned long vdp_ackdelay(void)
{
	return cmd_on[VDP_ACK].value;
}

static unsigned long vdp_error(void)
{
	return cmd_on[VDP_ERROR].value;
}

static void showmsg(char *txt, char nl, unsigned char *buf, int len)
{
	int i, do_nl = 1;

	printf("%s%c", txt, nl);
	for (i = 1; i <= len; ++i) {
		printf("%02x ", *buf++);
		do_nl = 1;
		if (i % 16 == 0) {
			printf("\n");
			do_nl = 0;
		}
	}
	if (do_nl)
		printf("\n");
}

/*
 * Convert a number from ascii to int.
 */
static unsigned long getnumber(char *key, char *word, char stopchar, int *ec)
{
	char *endp;
	unsigned long no = strtoul((const char *)word, &endp, 0);

	if (word == 0 || *word == '\0') {
		fprintf(stderr, "key %s has missing number\n", key);
		*ec = 1;
		return 0;
	}
#if MYDEBUG
	printf("%s:stopchar:%c endp:%c\n", __func__, stopchar, *endp);
#endif
	if (*endp != stopchar) {
		fprintf(stderr, "key %s has invalid parameter %s\n", key, word);
		*ec = 1;
		return 0;
	}
	*ec = 0;
	return no;
}

/*
 * Add a command to the list on how to react to unsolicited messages.
 * If not recognized, proceed with normal input processing.
 *
 * Currently recognized:
 * ecp ack 0 --> no delay in sending out acknowledgement
 * ecp ack 1..20 --> x seconds delay in sending out acknowledgement
 * ecp ack 21 --> no acknowledgement
 * vdp ack ## --> same as ecp ack
 * vdp error ## --> return error number on VDP request.
 */
static struct pr_op *valid_cmd()
{
	unsigned long no;
	int ec;

	struct pr_op *p = calloc(1, sizeof *p);

	if (!p) {
		perror(progname);
		exit(1);
	}
	if (!strcmp(tokens[1], "vdp") && !strcmp(tokens[2], "error")) {
		no = getnumber(tokens[2], tokens[3], '\0', &ec);
		if (ec)
			exit(1);
		p->value = no;
		p->type = VDP_ERROR;
		return p;
	}
	if (!strcmp(tokens[1], "vdp") && !strcmp(tokens[2], "ack")) {
		no = getnumber(tokens[2], tokens[3], '\0', &ec);
		if (ec)
			exit(1);
		if (no > VDPMAXACK)
			no = VDPMAXACK;
		p->value = no;
		p->type = VDP_ACK;
		return p;
	}
	if (!strcmp(tokens[1], "ecp") && !strcmp(tokens[2], "seqno")) {
		no = getnumber(tokens[2], tokens[3], '\0', &ec);
		if (ec)
			exit(1);
		p->value = no;
		p->type = ECP_SEQNO;
		return p;
	}
	if (!strcmp(tokens[1], "ecp") && !strcmp(tokens[2], "ack")) {
		no = getnumber(tokens[2], tokens[3], '\0', &ec);
		if (ec)
			exit(1);
		if (no > ECPMAXACK)
			no = ECPMAXACK;
		p->value = no;
		p->type = ECP_ACK;
		return p;
	}
	free(p);
	return 0;
}

static int numeric(unsigned char x)
{
	if (isdigit(x))
		return x - '0';
	return x - 97 + 10;
}

/*
 * Convert string to hex.
 */
static void mkbin(unsigned char *to, unsigned char *s)
{
	int byte1, byte2;

	for (; *s != '\0'; ++s) {
		byte1 = numeric(*s++);
		byte2 = numeric(*s);
		byte1 = byte1 << 4 | byte2;
		*to++ = byte1;
		if (*s == '\0')
			return;
	}
}

static unsigned char *validate(char *s, unsigned short *len)
{
	unsigned char buf[512], *cp = buf;
	int pos = 0;

#if MYDEBUG
	printf("%s:%s\n", __func__, s);
#endif
	if (!strcmp("-", (const char *)s)) {
		cp = calloc(ETH_ALEN, sizeof *cp);
		if (!cp) {
			perror(progname);
			exit(2);
		}
		memcpy(cp, my_mac, ETH_ALEN);
		return cp;
	}
	memset(buf, 0, sizeof buf);
	for (; *s != '\0'; ++s) {
		++pos;
		if (isxdigit(*s))
			*cp++ = isupper(*s) ? tolower(*s) : *s;
		else if (*s == ':') {
			if (pos % 3 != 0) {
				fprintf(stderr, "%s:invalid input format:%s\n",
				    progname, s);
				exit(2);
			}
			continue;
		} else {
			fprintf(stderr, "invalid data in input:%s\n", s);
			exit(2);
		}
	}
	*cp = '\0';
	pos = (strlen((const char *)buf) + 1) / 2;
#if MYDEBUG
	printf("%s:%s binary length:%d\n", __func__, buf, pos);
#endif
	cp = calloc(pos, sizeof *cp);
	if (!cp) {
		perror(progname);
		exit(2);
	}
	mkbin(cp, buf);
#if MYDEBUG
	showmsg("validate", ':', cp, pos);
#endif
	if (len)
		*len = pos;
	return cp;
}
static void removedataunit(struct lldpdu *q)
{
	free(q->data);
	free(q);
}

static void removedata(struct lldpdu *dup)
{
	struct lldpdu *q;

	while (dup) {
		q = dup;
		dup = dup->next;
		removedataunit(q);
	}
}

static void removeentry(struct lldp *p)
{
#if MYDEBUG
	printf("%s %p:\n", __func__, p);
#endif
	removedata(p->head);
	removedata(p->recv);
	free(p->opr);
	free(p->dst);
	free(p->src);
	free(p->ether);
	free(p);
}

static void show_cmd(struct pr_op *p)
{
	char *txt = "unknown";

	switch (p->type) {
	case ECP_SEQNO:
			txt = "ecp seqno";
			break;
	case ECP_ACK:
			txt = "ecp ack";
			break;
	case VDP_ACK:
			txt = "vdp ack";
			break;
	case VDP_ERROR:
			txt = "vdp error";
			break;
	case CMD_LAST:
			break;
	}
	printf("\t%s %ld\n", txt, p->value);
}

/*
 * Display one node entry on stdout.
 */
static void showentry(char *txt, struct lldp *p)
{
	struct lldpdu *dup;

#if MYDEBUG
	printf("%p: ", p);
#endif
	printf("%s time:%ld\n", txt, p->time);
	if (p->opr) {
		show_cmd(p->opr);
		return;
	}
	showmsg("\tdstmac", ':', p->dst, ETH_ALEN);
	showmsg("\tsrcmac", ':', p->src, ETH_ALEN);
	showmsg("\tethtype", ':', p->ether, 2);
	for (dup = p->head; dup; dup = dup->next)
		showmsg("\tout", ':', dup->data, dup->len);
	for (dup = p->recv; dup; dup = dup->next)
		showmsg("\tin", ':', dup->data, dup->len);
}

static int show_queue(char *txt, struct lldp *p)
{
	int cnt = 0;

	for (; p; p = p->next, ++cnt)
		showentry(txt, p);
	return cnt;
}

/*
 * Delete a complete lldp queue.
 */
static void delete_queue(struct lldp **root)
{
	struct lldp *node, *p = *root;

	while (p) {
		node = p;
		p = p->next;
		removeentry(node);
	}
	*root = 0;
}

/*
 * Append a node to expected reply queue.
 */
static void appendnode(struct lldp **root, struct lldp *add)
{
	struct lldp *p2 = *root;

	if (!p2) {			/* Empty queue */
		*root = add;
		return;
	}
	for (; p2->next; p2 = p2->next)
		;
	p2->next = add;
}

/*
 * Timer expired. Check if evb reply received. There is only one EVB message
 * pending for expected reply.
 */
static void timeout_evb(void)
{
	if (er_evb) {
		fprintf(stderr, "missing EVB reply (time:%ld)\n", er_evb->time);
		showentry("missing EVB reply", er_evb);
		delete_queue(&er_evb);
	}
}

static void appendentry(struct lldp *add)
{
	int type = memcmp(add->ether, eth_p_lldp, sizeof eth_p_lldp);

	if (type == 0)
		timeout_evb();
	appendnode(type == 0 ? &er_evb : &er_ecp, add);
}

/*
 * Insert node into queue.
 * Sorting criteria is time in ascending order.
 * There is only one entry for the evb reply queue and multiple entries for
 * the ecp reply queue for each time entry.
 */
static void insertentry(struct lldp *add)
{
	struct lldp *p2;
	int type;

	if (!lldphead) {			/* Empty queue */
		lldphead = add;
		return;
	}
	type = memcmp(add->ether, eth_p_lldp, sizeof eth_p_lldp);
	if (add->time <= lldphead->time) {	/* Insert at head */
		if (type == 0 && add->time == lldphead->time) {
			showentry("duplicate entry -- ignored", add);
			removeentry(add);
			return;
		}
		add->next = lldphead;
		lldphead = add;
		return;
	}
	for (p2 = lldphead; p2->next && add->time > p2->next->time;
						p2 = p2->next)
		;
	if (type == 0 && p2->next && add->time == p2->next->time) {
		showentry("duplicate entry -- ignored", add);
		removeentry(add);
		return;
	}
	add->next = p2->next;
	p2->next = add;
}

static int addone(void)
{
	struct lldp *p = calloc(1, sizeof *p);
	struct lldpdu *dup, *dup2;
	unsigned int i;
	int ec;

	if (!p) {
		perror("addone");
		return 1;
	}
	p->time = getnumber("time", tokens[0], '\0', &ec);
	if (ec)
		exit(3);
	p->opr = valid_cmd();
	if (p->opr) {
		char ecp_str[8];

		sprintf(ecp_str, "%02x:%02x", eth_p_ecp[0], eth_p_ecp[1]);
		p->ether = validate(ecp_str, 0);
		goto out;
	}
	p->dst = validate(tokens[1], 0);
	p->src = validate(tokens[2], 0);
	p->ether = validate(tokens[3], 0);
	if (memcmp(p->ether, eth_p_lldp, sizeof eth_p_lldp)
	&& memcmp(p->ether, eth_p_ecp, sizeof eth_p_ecp)) {
		fprintf(stderr, "%s: unsupported ethernet protocol %s\n",
			progname, tokens[3]);
		exit(11);
	}
	for (i = 4; i < DIM(tokens) && tokens[i]; ++i) {
		if ((dup = calloc(1, sizeof *dup))) {
			if (*tokens[i] == '@') {
				dup->data = validate(++tokens[i], &dup->len);
				if (p->recv) {
					for (dup2 = p->recv; dup2->next;
							dup2 = dup2->next)
						;
					dup2->next = dup;
				} else
					p->recv = dup;
				continue;
			}
			dup->data = validate(tokens[i], &dup->len);
			if (p->head) {
				for (dup2 = p->head; dup2->next;
							dup2 = dup2->next)
					;
				dup2->next = dup;
			} else
				p->head = dup;
		} else {
			perror("addone2");
			return 1;
		}
	}
out:
	insertentry(p);
	return 0;
}

static void settokens(char *parm)
{
	unsigned int i;

	for (i = 0; i < DIM(tokens) && (tokens[i] = strtok(parm, "\t ")) != 0;
	    ++i, parm = 0) {
#if MYDEBUG
		printf("%s:tokens[%d]:%s:\n", __func__, i, tokens[i]);
#endif
	}
}

static int forwardline(char *line)
{
	settokens(line);
	return addone();
}

/*
 * Read a full line from the file. Remove comments and ignore blank lines.
 * Also concatenate lines terminated with <backslash><newline>.
 */
#define	COMMENT	"#*;"		/* Comments in [#*;] and <newline> */
static char *fullline(FILE *fp, char *buffer, size_t buflen)
{
	int more = 0, off = 0;
	char *cp;
	static int lineno;

	do {
		if ((cp = fgets(buffer + off, buflen - off, fp)) == NULL) {
			if (more == 2) {
				fprintf(stderr, "%s line %d unexpected EOF\n",
				    progname, lineno);
				exit(1);
			}
			return NULL;	/* No more lines */
		}
		++lineno;
		if ((cp = strchr(buffer, '\n')) == NULL) {
			fprintf(stderr, "%s line %d too long", progname,
			    lineno);
			exit(1);
		} else
			*cp = '\0';
		if ((cp = strpbrk(buffer, COMMENT)) != NULL)
			*cp = '\0';	/* Drop comment */
		for (cp = buffer; *cp && isspace(*cp); ++cp)
			;	/* Skip leading space */
		if (*cp == '\0')
			more = 1;	/* Empty line */
		else if (*(cp + strlen(cp) - 1) == '\\') {
			more = 2;	/* Line concatenation */
			*(cp + strlen(cp) - 1) = '\0';
			off = strlen(buffer);
		} else
			more = 0;
	} while (more);
	memmove(buffer, cp, strlen(cp) + 1);
	return buffer;
}

/*
 * Read the configuration file containing the LLDP DUs.
 */
static int read_profiles(char *cfgfile)
{
	FILE *fp;
	char buffer[1024 * 5];
	char cmd[128];
	int rc = 0;

	sprintf(cmd, "cpp %s", cfgfile);
	if ((fp = popen(cmd, "r")) == NULL) {
		perror(cmd);
		exit(1);
	}
	while (fullline(fp, buffer, sizeof buffer))
		rc |= forwardline(buffer);
	pclose(fp);
	return rc;
}

static int tlv_id(unsigned char *outp)
{
	return *outp >> 1;
}

static int tlv_len(unsigned char *outp)
{
	int byte1 = *outp & 1;
	int byte2 = *(outp + 1);

	return byte1 << 8 | byte2;
}

static void l2_close(int fd)
{
	close(fd);
}

static const unsigned char nearest_bridge[ETH_ALEN] = {
	0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e
};

static const unsigned char nearest_nontpmr_bridge[ETH_ALEN] = {
	0x01, 0x80, 0xc2, 0x00, 0x00, 0x03
};

static const unsigned char nearest_customer_bridge[ETH_ALEN] = {
	0x01, 0x80, 0xc2, 0x00, 0x00, 0x00
};

static int l2_init(char *ifname, unsigned short pno)
{
	struct ifreq ifr;
	struct sockaddr_ll ll;
	struct packet_mreq mr;
	int ifindex, option = 1;
	int option_size = sizeof(option);
	int fd;

	fd = socket(PF_PACKET, SOCK_RAW, htons(pno));
	if (fd < 0) {
		perror("socket(PF_PACKET)");
		return -1;
	}
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl[SIOCGIFINDEX]");
		close(fd);
		return -1;
	}
	ifindex = ifr.ifr_ifindex;
	memset(&ll, 0, sizeof(ll));
	ll.sll_family = PF_PACKET;
	ll.sll_ifindex = ifr.ifr_ifindex;
	ll.sll_protocol = htons(pno);
	if (bind(fd, (struct sockaddr *)&ll, sizeof(ll)) < 0) {
		perror("bind[PF_PACKET]");
		close(fd);
		return -1;
	}
	/* current hw address */
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl[SIOCGIFHWADDR]");
		close(fd);
		return -1;
	}
	memcpy(my_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	if (verbose)
		printf("%s MAC address is " MACSTR "\n", ifname,
			MAC2STR(my_mac));
	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = ifindex;
	mr.mr_alen = ETH_ALEN;
	memcpy(mr.mr_address, &nearest_bridge, ETH_ALEN);
	mr.mr_type = PACKET_MR_MULTICAST;
	if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr,
		sizeof(mr)) < 0) {
		perror("setsockopt nearest_bridge");
		close(fd);
		return -1;
	}
	memcpy(mr.mr_address, &nearest_customer_bridge, ETH_ALEN);
	if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr,
		sizeof(mr)) < 0)
		perror("setsockopt nearest_customer_bridge");
	memcpy(mr.mr_address, &nearest_nontpmr_bridge, ETH_ALEN);
	if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr,
		sizeof(mr)) < 0)
		perror("setsockopt nearest_nontpmr_bridge");
	if (setsockopt(fd, SOL_PACKET, PACKET_ORIGDEV,
		&option, option_size) < 0) {
		perror("setsockopt SOL_PACKET");
		close(fd);
		return -1;
	}
	return fd;
}

static void apply_cmd(struct pr_op *p)
{
	switch (p->type) {
	case ECP_SEQNO:
			cmd_on[ECP_SEQNO].value = p->value;
			if (verbose >= 2)
				show_cmd(p);
			break;
	case ECP_ACK:
			cmd_on[ECP_ACK].value = p->value;
			if (verbose >= 2)
				show_cmd(p);
			break;
	case VDP_ACK:
			cmd_on[VDP_ACK].value = p->value;
			if (verbose >= 2)
				show_cmd(p);
			break;
	case VDP_ERROR:
			cmd_on[VDP_ERROR].value = p->value;
			if (verbose >= 2)
				show_cmd(p);
			break;
	case CMD_LAST:
			break;
	}
}

/*
 * Send one entry. Return 0 on failure and number of bytes on success.
 */
static int sendentry(struct lldp *p)
{
	struct lldpdu *dup;
	unsigned char out[2300];
	char tracebuf[128];
	struct ethhdr *ehdr = (struct ethhdr *)out;
	unsigned char *outp = out + sizeof *ehdr;
	int fd = -1;
	int len;

	if (p->opr) {
		apply_cmd(p->opr);
		return 0;
	}
	memset(out, 0, sizeof out);
	memcpy(ehdr->h_dest, p->dst, ETH_ALEN);
	memcpy(ehdr->h_source, p->src, ETH_ALEN);
	memcpy(&ehdr->h_proto, p->ether, 2);
	for (dup = p->head; dup; dup = dup->next) {
		memcpy(outp, dup->data, dup->len);
		outp += dup->len;
	}
	if (verbose >= 2) {
		sprintf(tracebuf, "sendout time(%ld)", p->time);
		showmsg(tracebuf, '\n', out, outp - out);
	}
	if (!memcmp(p->ether, eth_p_lldp, sizeof eth_p_lldp))
		fd = myfd;
	else
		fd = ecpfd;
	len = send(fd, out, outp - out, 0);
	if (len != outp - out) {
		fprintf(stderr, "%s:send error %d bytes:%ld\n", __func__, len,
		    outp - out);
		len = 0;
	}
	return len;
}

/*
 * Get first entry from list which is equal or older than current program
 * run time and remove it from list.
 *
 * Return pointer to node or 0.
 */
static struct lldp *findentry(struct lldp **root)
{
	struct lldp *p = *root;

	if (p && runtime >= p->time) {
		*root = p->next;
		p->next = 0;
		return p;
	}
	return 0;
}

static void sendall(void)
{
	struct lldp *p;
	long long int expired;

	if (read(timerfd, &expired, sizeof expired) != sizeof expired) {
		fprintf(stderr, "%s:read error %d bytes:%ld\n", __func__, errno,
			sizeof expired);
		return;
	}
	for (p = findentry(&lldphead); p; p = findentry(&lldphead)) {
		if (sendentry(p) && p->recv)
			appendentry(p);
		else
			removeentry(p);
	}
}

/*
 * Check if an expected TLV is in the ECP/LLDP DU reply.
 * Return 1 if it matches and has been removed from the data unit list.
 */
static int check_tlv(struct lldp *node, unsigned char *tlv)
{
	struct lldpdu *dup = node->recv;
	struct lldpdu *dup_pr = 0;

	while (dup) {
		if (!memcmp(tlv, dup->data, dup->len)) {
			char txt[32];

			if (verbose >= 2) {
				sprintf(txt, "tlv id:%d len:%d",
					tlv_id(dup->data), tlv_len(dup->data));
				showmsg(txt, ':', tlv, dup->len);
			}
			if (dup_pr)
				dup_pr->next = dup->next;
			else
				node->recv = dup->next;
			removedataunit(dup);
			return 1;
		}
		dup_pr = dup;
		dup = dup->next;
	}
	return 0;
}

/*
 * Show all TLV expected in a reply.
 */
static void show_expect(struct lldp *node, int exitcode)
{
	struct lldpdu *dup = node->recv;
	char txt[32];

	if (verbose)
		printf("ERROR expected reply for message sent at %ld sec missing\n",
			node->time);
	while (dup) {
		if (verbose) {
			sprintf(txt, "tlv-id:%d len:%d", tlv_id(dup->data),
					tlv_len(dup->data));
			showmsg(txt, ':', dup->data, 2 + tlv_len(dup->data));
		}
		dup = dup->next;
	}
	exit(exitcode);
}

/*
 * Check if the received reply contains this data we expect as response.
 */
static void search_evbreply(unsigned char *buf, size_t buflen)
{
	struct ethhdr *ehdr = (struct ethhdr *)buf;
	unsigned char *tlv = (unsigned char *)(ehdr + 1);
	int del = 0;

	if (!er_evb || !er_evb->recv)		/* No reply expected */
		return;
	do {
		int len = 2 + tlv_len(tlv);

		if (tlv_id(tlv))
			del += check_tlv(er_evb, tlv);
		tlv += len;
	} while (tlv < buf + buflen);
	if (er_evb->recv)
		show_expect(er_evb, 5);
	/* Got all expected replies, delete queue */
	delete_queue(&er_evb);
}

/*
 * Wait for a message from switch
 *
 * Return number of bytes received. 0 means timeout and -1 on error.
 */
static int get_evb(void)
{
	unsigned char buf[2300];
	size_t buflen = sizeof buf;
	struct sockaddr_ll from;
	socklen_t from_len = sizeof from;
	int result = 0;

	memset(buf, 0, buflen);
	memset(&from, 0, from_len);
	result = recvfrom(myfd, buf, buflen, 0, (struct sockaddr *)&from,
			&from_len);
	if (result < 0)
		fprintf(stderr, "%s receive error:%s\n",
		    progname, strerror(errno));
	else {
		if (verbose)
			printf("received %d bytes from ifindex %d\n",
			    result, from.sll_ifindex);
		if (verbose >= 2)
			printf("\tfamily:%hd protocol:%hx hatype:%hd\n"
			    "\tpkttype:%d halen:%d MAC:" MACSTR "\n",
			    from.sll_family, ntohs(from.sll_protocol),
			    from.sll_hatype, from.sll_pkttype,
			    from.sll_halen, MAC2STR(from.sll_addr));
		if (result > 0) {
			if (verbose >= 2)
				showmsg("get_evb", ':', buf, result);
			search_evbreply(buf, result);
		}
	}
	return result;
}

/*
 * Pack the vdp data into the buffer. For now just use the first 3 bytes.
 */
static void convert_vdp(unsigned char *load, struct vdphdr *p)
{
	*load = (p->opr << 1);
	*(load + 1) = 1;
	*(load + 2) = p->status;
}

/*
 * Pack the ecp header into 4 bytes.
 */
static void convert_ecp(unsigned char *load, struct ecphdr *ecp)
{
	*load = (ecp->version << 4) | (ecp->op << 2)
		| ((ecp->subtype >> 8) & 0xff);
	*(load + 1) = ecp->subtype & 0xff;
	*(load + 2) = ecp->seqno >> 8 & 0xff;
	*(load + 3) = ecp->seqno & 0xff;
}

/*
 * Check if this vdp data needs acknowledgement, Return false in this case
 * true otherwise.
 */
static int vdp_get(unsigned char *vdpdata, int len, struct vdphdr *vdp)
{
	unsigned char tlv_type = tlv_id(vdpdata);
	unsigned short tlv_length = tlv_len(vdpdata);

	memset(vdp, 0, sizeof *vdp);
	for ( ; tlv_type >= 5 && len >= 0;
			len -= tlv_length + 2, vdpdata += tlv_length + 2)
		;
	if (tlv_type < 5) {
		vdp->opr = tlv_id(vdpdata);
		vdpdata += 2;
		vdp->status = *vdpdata;
		vdp->vsi_tyid = *(vdpdata + 1) << 16 | *(vdpdata + 2) << 8 |
				*(vdpdata + 3);
		vdp->vsi_tyv = *(vdpdata + 4);
		vdp->vsi_tyfm = *(vdpdata + 5);
		memcpy(vdp->vsi_uuid, vdpdata + 6, sizeof vdp->vsi_uuid);
		vdp->fil_info = *(vdpdata + 22);
		if ((vdp->status & 2) == 0)
			return 0;
	}
	return 1;
}

/*
 * Handle acknowledgement of vdp protocol header.
 */
static void handle_vdp(unsigned char *data, int len)
{
	unsigned char *load, *rcv, *dst, *src, *ether;
	struct lldp *ack;
	struct lldpdu *ackdata, *rcvdata;
	struct ethhdr *ethhdr = (struct ethhdr *)data;
	struct vdphdr vdp;
	struct ecphdr ecp;

	if (vdp_ackdelay() > VDPMAXACK)	/* Acknowledge request */
		return;
	if (vdp_get(data + ETH_HLEN + ECP_HLEN, len - (ETH_HLEN + ECP_HLEN),
		    &vdp))
		return;
	ack = calloc(1, sizeof *ack);
	ackdata = calloc(1, sizeof *ackdata);
	rcvdata = calloc(1, sizeof *rcvdata);
	load = calloc(ECP_HLEN + 3, sizeof *load);
	rcv = calloc(ECP_HLEN, sizeof *load);
	dst = calloc(ETH_ALEN, sizeof *dst);
	src = calloc(ETH_ALEN, sizeof *src);
	ether = calloc(2, sizeof *ether);
	if (!ack || !ackdata || !load || !dst || !src || !ether || !rcv ||
			!rcvdata) {
		free(load);
		free(rcv);
		free(dst);
		free(src);
		free(ether);
		free(ackdata);
		free(rcvdata);
		free(ack);
		return;
	}
	ack->time = runtime + vdp_ackdelay();
	/* Prepare ETH header */
	ack->dst = dst;
	memcpy(ack->dst, ethhdr->h_source, sizeof ethhdr->h_source);
	ack->src = src;
	memcpy(ack->src, my_mac, sizeof ethhdr->h_source);
	ack->ether = ether;
	memcpy(ack->ether, eth_p_ecp, sizeof ethhdr->h_proto);
	/* Prepare ECP header */
	ecp.op = 0;
	ecp.seqno = ecp_inc_seqno();
	ecp.subtype = 1;
	ecp.version = 1;
	convert_ecp(load, &ecp);
	/* Prepare ECP acknowledgement */
	ecp.op = 1;
	convert_ecp(rcv, &ecp);
	rcvdata->data = rcv;
	rcvdata->len = ECP_HLEN;
	ack->recv = rcvdata;
	/* Prepare VDP acknowledgement */
	vdp.status = ((vdp_error() & 0xf) << 4) | 2;
	convert_vdp(load + ECP_HLEN, &vdp);
	ackdata->data = load;
	ackdata->len = ECP_HLEN + 3;
	ack->head = ackdata;
	if (vdp_ackdelay()) {		/* Insert ack in queue */
		insertentry(ack);
		return;
	}
	sendentry(ack);
	appendnode(&er_ecp, ack);
}

/*
 * Send out acknowledgement when request received.
 */
static void ack_ecp(unsigned char *ecpdata, struct ecphdr *ecp)
{
	unsigned char *load, *dst, *src, *ether;
	struct lldp *ack;
	struct lldpdu *ackdata;
	struct ethhdr *ethhdr = (struct ethhdr *)ecpdata;

	if (ecp_ackdelay() > ECPMAXACK)	/* Acknowledge request */
		return;
	ack = calloc(1, sizeof *ack);
	ackdata = calloc(1, sizeof *ackdata);
	load = calloc(ECP_HLEN, sizeof *load);
	dst = calloc(ETH_ALEN, sizeof *dst);
	src = calloc(ETH_ALEN, sizeof *src);
	ether = calloc(2, sizeof *ether);
	if (!ack || !ackdata || !load || !dst || !src || !ether) {
		free(ack);
		free(ackdata);
		free(load);
		free(dst);
		free(src);
		free(ether);
		return;
	}
	ack->time = runtime + ecp_ackdelay();
	ack->dst = dst;
	memcpy(ack->dst, ethhdr->h_source, sizeof ethhdr->h_source);
	ack->src = src;
	memcpy(ack->src, my_mac, sizeof ethhdr->h_source);
	ack->ether = ether;
	memcpy(ack->ether, eth_p_ecp, sizeof ethhdr->h_proto);
	ecp->op = 1;
	convert_ecp(load, ecp);
	ackdata->data = load;
	ackdata->len = ECP_HLEN;
	ack->head = ackdata;
	if (ecp_ackdelay()) {		/* Insert ack in queue */
		insertentry(ack);
		return;
	}
	sendentry(ack);
	removeentry(ack);
}

/*
 * Show ECP expected in a reply.
 */
static void show_ecpexpect(struct lldp *node, int exitcode)
{
	struct lldpdu *dup = node->recv;

	if (verbose)
		printf("ERROR expected ECP ACK for message sent at %ld sec missing\n",
			node->time);
	while (dup) {
		if (verbose)
			showmsg("ecp-ack", ':', dup->data, dup->len);
		dup = dup->next;
	}
	exit(exitcode);
}
/*
 * Check if an expected TLV is in the ECP/LLDP DU reply.
 * Return 1 if it matches and has been removed from the data unit list.
 */
static int check_ecpack(struct lldp *node, unsigned char *buf)
{
	struct lldpdu *dup = node->recv;
	struct lldpdu *dup_pr = 0;

	while (dup) {
		if (!memcmp(buf, dup->data, dup->len)) {
			if (dup_pr)
				dup_pr->next = dup->next;
			else
				node->recv = dup->next;
			removedataunit(dup);
			return 1;
		}
		dup_pr = dup;
		dup = dup->next;
	}
	return 0;
}

/*
 * Find an ECP send command and check the returned acknowledgement.
 */
static void search_ecpack(unsigned char *ecpdata)
{
	struct lldp *np, *np_prev = 0;

	for (np = er_ecp; np; np_prev = np, np = np->next) {
		check_ecpack(np, ecpdata + ETH_HLEN);
		if (np->recv)
			show_ecpexpect(np, 6);
		else {
			if (!np_prev)
				er_ecp = np->next;
			else
				np_prev->next = np->next;
			removeentry(np);
		}
	}
}

static int handle_ecp(unsigned char *ecpdata)
{
	unsigned char *buf = ecpdata + ETH_HLEN;
	struct ecphdr ecphdr;
	int rc = 0;

	ecphdr.version = *buf >> 4;
	ecphdr.op = (*buf >> 2) & 3;
	ecphdr.subtype = (*buf & 3) << 8 | *(buf + 1);
	ecphdr.seqno = *(buf + 2) << 8 | *(buf + 3);
	if (verbose >= 2)
		printf("ecp.version:%d op:%d subtype:%d seqno:%#hx\n",
		       ecphdr.version, ecphdr.op, ecphdr.subtype,
		       ecphdr.seqno);
	if (ecphdr.op == 0) {		/* Request received, send ACK */
		ack_ecp(ecpdata, &ecphdr);
		rc = ecphdr.subtype;
	} else				/* ACK received, check list */
		search_ecpack(ecpdata);
	return rc;
}

static int get_ecp(void)
{
	unsigned char buf[2300];
	size_t buflen = sizeof buf;
	struct sockaddr_ll from;
	socklen_t from_len = sizeof from;
	int type, result = 0;

	memset(buf, 0, buflen);
	memset(&from, 0, from_len);
	result = recvfrom(ecpfd, buf, buflen, 0, (struct sockaddr *)&from,
			&from_len);
	if (result < 0)
		fprintf(stderr, "%s receive error:%s\n",
		    progname, strerror(errno));
	else {
		if (verbose)
			printf("received %d bytes from ifindex %d\n",
			    result, from.sll_ifindex);
		if (verbose >= 2)
			printf("\tfamily:%hd protocol:%hx hatype:%hd\n"
			    "\tpkttype:%d halen:%d MAC:" MACSTR "\n",
			    from.sll_family, ntohs(from.sll_protocol),
			    from.sll_hatype, from.sll_pkttype,
			    from.sll_halen, MAC2STR(from.sll_addr));
		if (result > 0) {
			if (verbose >= 2)
				showmsg("get_ecp", ':', buf, result);
			type = handle_ecp(buf);
			if (type == 1)		/* VDP payload in ECP */
				handle_vdp(buf, result);
		}
	}
	return result;
}

/*
 * c := a - b, with a->tv_sec always larger or equal than b->tv_sec
 */
static void past(struct timespec *a, struct timespec *b, struct timespec *c)
{
	c->tv_sec = a->tv_sec - b->tv_sec;
	if (a->tv_nsec > b->tv_nsec)
		c->tv_nsec = a->tv_nsec - b->tv_nsec;
	else {
		c->tv_nsec = 1000000000 - b->tv_nsec + a->tv_nsec;
		--c->tv_sec;
	}
}

static void timer_init(void)
{
	struct itimerspec val;

	if ((timerfd = timerfd_create(CLOCK_MONOTONIC, 0)) < 0) {
		perror(progname);
		exit(2);
	}
	val.it_value.tv_sec = timeout;
	val.it_value.tv_nsec = timeout_us;
	val.it_interval.tv_sec = timeout;
	val.it_interval.tv_nsec = timeout_us;
	if (timerfd_settime(timerfd, 0, &val, 0) != 0) {
		perror(progname);
		exit(2);
	}
}

static void timer_close(void)
{
	struct itimerspec val;

	val.it_value.tv_sec = 0;
	val.it_value.tv_nsec = 0;
	val.it_interval.tv_sec = 0;
	val.it_interval.tv_nsec = 0;
	timerfd_settime(timerfd, 0, &val, 0);
	close(timerfd);
}

static void hear(void)
{
	int n, cnt = 0;
	struct timespec start_time, now, diff;
	fd_set readfds;

	timer_init();
	clock_gettime(CLOCK_MONOTONIC, &start_time);
	do {
		FD_ZERO(&readfds);
		FD_SET(ecpfd, &readfds);
		FD_SET(myfd, &readfds);
		FD_SET(timerfd, &readfds);
		if (verbose)
			printf("%s wait for event %d...", progname, ++cnt);
		n = (myfd > timerfd) ? myfd : timerfd;
		n = (n > ecpfd) ? n : ecpfd;
		n = select(n + 1, &readfds, NULL, NULL, 0);
		clock_gettime(CLOCK_MONOTONIC, &now);
		past(&now, &start_time, &diff);
		runtime = diff.tv_sec;
		if (n < 0) {
			fprintf(stderr, "%s error select:%s\n", progname,
				strerror(errno));
		} else {
			if (FD_ISSET(ecpfd, &readfds)) {
				if (verbose >= 3)
					printf("ECP msg received %ld.%09ld\n",
						diff.tv_sec, diff.tv_nsec);
				get_ecp();
			}
			if (FD_ISSET(myfd, &readfds)) {
				if (verbose >= 3)
					printf("EVB msg received %ld.%09ld\n",
						diff.tv_sec, diff.tv_nsec);
				get_evb();
			}
			if (FD_ISSET(timerfd, &readfds)) {
				if (verbose >= 3)
					printf("timer expired %ld.%09ld\n",
						diff.tv_sec, diff.tv_nsec);
				else if (verbose)
					printf("\n");
				timeout_evb();
				sendall();
			}
		}
	} while ((unsigned long)diff.tv_sec < duration);
	timer_close();
}

static void help(void)
{
	printf("\t-a specifies the ECP acknowledgement delay ((default %lds)\n"
	       "\t-d specifies the run time of the program (default %ld)\n"
	       "\t-t specifies the timeout in seconds to wait (default %lds)\n"
	       "\t-T specifies the timeout in microseconds to wait"
	       " (default %ldus)\n"
	       "\t-v verbose mode, can be set more than once\n"
	       "\t device is the network interface to listen on\n"
	       "\t file is one or more input files to read LLDP data from\n",
	       ecp_ackdelay(), duration, timeout, timeout_us);
}

int main(int argc, char **argv)
{
	extern int optind, opterr;
	extern char *optarg;
	int rc = 0, ch;
	char *slash;

	progname = (slash = strrchr(argv[0], '/')) ? slash + 1 : argv[0];
	while ((ch = getopt(argc, argv, ":d:t:T:v")) != EOF)
		switch (ch) {
		case '?':
			fprintf(stderr, "%s: unknown option -%c\n", progname,
			    optopt);
			help();
			exit(1);
		case ':':
			fprintf(stderr, "%s missing option argument for -%c\n",
			    progname, optopt);
			exit(1);
		case 'T':
			timeout_us = strtoul(optarg, 0, 0);
			if (!timeout_us) {
				fprintf(stderr, "%s wrong timeout %s\n",
				    progname, optarg);
				exit(1);
			}
			break;
		case 't':
			timeout = strtoul(optarg, 0, 0);
			if (!timeout) {
				fprintf(stderr, "%s wrong timeout %s\n",
				    progname, optarg);
				exit(1);
			}
			break;
		case 'd':
			duration = strtoul(optarg, 0, 0);
			if (!duration) {
				fprintf(stderr, "%s wrong duration %s\n",
				    progname, optarg);
				exit(1);
			}
			break;
		case 'v':
			++verbose;
			break;
		}
	if (argc == optind) {
		fprintf(stderr, "%s interface not specified\n", progname);
		return 2;
	}
	if (!if_nametoindex(argv[optind])) {
		fprintf(stderr, "%s interface %s does not exist\n",
		    progname, argv[optind]);
		return 2;
	}
	myfd = l2_init(argv[optind], ETH_P_LLDP);
	if (myfd < 0)
		return 2;
	ecpfd = l2_init(argv[optind], ETH_P_ECP);
	if (ecpfd < 0) {
		l2_close(myfd);
		return 2;
	}
	for (; ++optind < argc;) {
		rc |= read_profiles(argv[optind]);
		if (verbose >= 3)
			show_queue("command", lldphead);
	}
	hear();
	l2_close(ecpfd);
	l2_close(myfd);
	show_queue("expected evb replies", er_evb);
	if (show_queue("expected ecp replies", er_ecp))
		rc = 7;		/* This queue should be empty */
	return rc;
}
