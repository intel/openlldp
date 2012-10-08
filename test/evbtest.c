/******************************************************************************

  Implementation of VDP according to IEEE 802.1Qbg
  (c) Copyright IBM Corp. 2012

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
#define MACSTR		"%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC2STR(a)	(a)[0] & 0xff, (a)[1] & 0xff, (a)[2] & 0xff, \
			(a)[3] & 0xff, (a)[4] & 0xff, (a)[5] & 0xff

static char *progname;

static int verbose;
static char *tokens[1024];	/* Used to parse command line params */
static int ifindex;		/* Index of ifname */
static char *ifname;		/* Interface to operate on */
static int myfd;		/* Raw socket for lldpad talk */
static int timerfd;		/* Time descriptor */
static unsigned char my_mac[ETH_ALEN];	/* My source MAC address */
static unsigned long duration = 120;	/* Time to run program in seconds */
static unsigned long timeout = 1;	/* Time to wait in select in seconds */
static unsigned long timeout_us = 0;	/* Time to wait in select in usecs */

struct lldpdu {			/* LLDP Data unit to send */
	unsigned char *data;
	struct lldpdu *next;
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
};

static struct lldp *lldphead;

static void showmsg(char *txt, unsigned char *buf, int len)
{
	int i;

	printf("%s:%s\n", __func__, txt);
	for (i = 1; i <= len; ++i) {
		printf("%02x ", *buf++);
		if (i % 16 == 0)
			printf("\n");
	}
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

static unsigned char *validate(char *s)
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
	showmsg("validate", cp, pos);
#endif
	return cp;
}

static int addone(void)
{
	struct lldp *p2, *p = calloc(1, sizeof *p);
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
	p->dst = validate(tokens[1]);
	p->src = validate(tokens[2]);
	p->ether = validate(tokens[3]);
	for (i = 4; i < DIM(tokens) && tokens[i]; ++i) {
		if ((dup = calloc(1, sizeof *dup))) {
			if (*tokens[i] == '@') {
				dup->data = validate(++tokens[i]);
				if (p->recv) {
					for (dup2 = p->recv; dup2->next;
							dup2 = dup2->next)
						;
					dup2->next = dup;
				} else
					p->recv = dup;
				continue;
			}
			dup->data = validate(tokens[i]);
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
	if (!lldphead)
		lldphead = p;
	else {
		for (p2 = lldphead; p2->next; p2 = p2->next)
			;
		p2->next = p;
	}
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

static void show_evblist(void)
{
	struct lldp *p = lldphead;

	for (; p; p = p->next) {
		struct lldpdu *dup;

		printf("%p time:%ld\n", p, p->time);
		showmsg("\tdstmac", p->dst, ETH_ALEN);
		showmsg("\tsrcmac", p->src, ETH_ALEN);
		showmsg("\tethtype", p->ether, 2);
		for (dup = p->head; dup; dup = dup->next)
			showmsg("\tout tlv", dup->data, 2 + tlv_len(dup->data));
		for (dup = p->recv; dup; dup = dup->next)
			showmsg("\tin tlv", dup->data, 2 + tlv_len(dup->data));
	}
}

static void l2_close(void)
{
	close(myfd);
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

static int l2_init(char *ifname)
{
	struct ifreq ifr;
	struct sockaddr_ll ll;
	struct packet_mreq mr;
	int ifindex, option = 1;
	int option_size = sizeof(option);

	myfd = socket(PF_PACKET, SOCK_RAW, htons(0x88cc));
	if (myfd < 0) {
		perror("socket(PF_PACKET)");
		return -1;
	}
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(myfd, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl[SIOCGIFINDEX]");
		close(myfd);
		return -1;
	}
	ifindex = ifr.ifr_ifindex;
	memset(&ll, 0, sizeof(ll));
	ll.sll_family = PF_PACKET;
	ll.sll_ifindex = ifr.ifr_ifindex;
	ll.sll_protocol = htons(0x88cc);
	if (bind(myfd, (struct sockaddr *)&ll, sizeof(ll)) < 0) {
		perror("bind[PF_PACKET]");
		close(myfd);
		return -1;
	}
	/* current hw address */
	if (ioctl(myfd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl[SIOCGIFHWADDR]");
		close(myfd);
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
	if (setsockopt(myfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr,
		sizeof(mr)) < 0) {
		perror("setsockopt nearest_bridge");
		close(myfd);
		return -1;
	}
	memcpy(mr.mr_address, &nearest_customer_bridge, ETH_ALEN);
	if (setsockopt(myfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr,
		sizeof(mr)) < 0)
		perror("setsockopt nearest_customer_bridge");
	memcpy(mr.mr_address, &nearest_nontpmr_bridge, ETH_ALEN);
	if (setsockopt(myfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr,
		sizeof(mr)) < 0)
		perror("setsockopt nearest_nontpmr_bridge");
	if (setsockopt(myfd, SOL_PACKET, PACKET_ORIGDEV,
		&option, option_size) < 0) {
		perror("setsockopt SOL_PACKET");
		close(myfd);
		return -1;
	}
	return 0;
}

static void removedata(struct lldpdu *dup)
{
	struct lldpdu *q;

	while (dup) {
		q = dup;
		dup = dup->next;
		free(q->data);
		free(q);
	}
}

static void removeentry(struct lldp *p)
{
	removedata(p->head);
	removedata(p->recv);
	lldphead = p->next;
	free(p);
}

static struct lldpdu *reply_du;			/* Expected TLVs */
static long reply_dutime;			/* Time they have been sent */

static void expect_reply(struct lldp *lldp)
{
	if (reply_du) {
		fprintf(stderr, "%s no reply for message sent out (%ld sec)\n",
			__func__, reply_dutime);
		if (verbose)
			showmsg("expect_reply", reply_du->data,
				2 + tlv_len(reply_du->data));
		removedata(reply_du);
		reply_du = 0;
	}
	if (!reply_du) {
		reply_du = lldp->recv;
		reply_dutime = lldp->time;
		lldp->recv = 0;
	}
}

static void sendentry(struct lldp *p)
{
	struct lldpdu *dup;
	unsigned char out[2300];
	char tracebuf[128];
	struct ethhdr *ehdr = (struct ethhdr *)out;
	unsigned char *outp = out + sizeof *ehdr;
	int len;

	memset(out, 0, sizeof out);
	memcpy(ehdr->h_dest, p->dst, ETH_ALEN);
	memcpy(ehdr->h_source, p->src, ETH_ALEN);
	memcpy(&ehdr->h_proto, p->ether, 2);
	for (dup = p->head; dup; dup = dup->next) {
		len = 2 + tlv_len(dup->data);
		memcpy(outp, dup->data, len);
		outp += len;
	}
	if (verbose >= 2) {
		sprintf(tracebuf, "time:%ld", p->time);
		showmsg(tracebuf, out, outp - out);
	}
	len = send(myfd, out, outp - out, 0);
	if (len != outp - out)
		fprintf(stderr, "%s:send error %d bytes:%ld\n", __func__, len,
		    outp - out);
	else if (p->recv)
		expect_reply(p);
}

static struct lldp *findentry(unsigned long runtime)
{
	struct lldp *p = lldphead;

	return (p && runtime >= p->time) ? p : 0;
}

static void sendall(unsigned long sec)
{
	struct lldp *p;
	long long int expired;

	if (read(timerfd, &expired, sizeof expired) != sizeof expired) {
		fprintf(stderr, "%s:read error %d bytes:%ld\n", __func__, errno,
			sizeof expired);
		return;
	}
	for (p = findentry(sec); p; p = findentry(sec)) {
		sendentry(p);
		removeentry(p);
	}
}

/*
 * Check if an expected TLV is in the LLDP DU reply and remove it from the list.
 */
static void check_tlv(unsigned char *tlv, int len)
{
	struct lldpdu *dup = reply_du;
	struct lldpdu *dup_pr = 0;

	while (dup) {
		if (!memcmp(tlv, dup->data, len)) {
			char txt[32];

			if (verbose >= 2) {
				sprintf(txt, "tlv id:%d len:%d",
					tlv_id(dup->data), tlv_len(dup->data));
				showmsg(txt, tlv, len);
			}
			if (dup_pr)
				dup_pr->next = dup->next;
			else
				reply_du = dup->next;
			free(dup);
			return;
		}
		dup_pr = dup;
		dup = dup->next;
	}
}

/*
 * Show all TLV expected in a reply.
 */
static void show_expect(int exitcode)
{
	char txt[32];
	struct lldpdu *dup = reply_du;

	if (verbose)
		printf("ERROR expected reply for message sent at %ld sec missing\n",
			reply_dutime);
	while (dup) {
		if (verbose) {
			sprintf(txt, "tlv-id:%d len:%d", tlv_id(dup->data),
					tlv_len(dup->data));
			showmsg(txt, dup->data, 2 + tlv_len(dup->data));
		}
		dup = dup->next;
	}
	exit(exitcode);
}

static void check_reply(unsigned char *buf, size_t buflen)
{
	struct ethhdr *ehdr = (struct ethhdr *)buf;
	unsigned char *tlv = (unsigned char *)(ehdr + 1);

	do {
		int len = 2 + tlv_len(tlv);

		if (tlv_id(tlv))
			check_tlv(tlv, len);
		tlv += len;
	} while (tlv < buf + buflen);
	if (reply_du)
		show_expect(5);
}

/*
 * Wait for a message from switch
 *
 * Return number of bytes received. 0 means timeout and -1 on error.
 */
static int getmsg(void)
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
				showmsg("recv", buf, result);
			if (reply_du)
				check_reply(buf, result);
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
		FD_SET(myfd, &readfds);
		FD_SET(timerfd, &readfds);
		if (verbose)
			printf("%s wait for event %d...", progname, ++cnt);
		n = (myfd > timerfd) ? myfd : timerfd;
		n = select(n + 1, &readfds, NULL, NULL, 0);
		clock_gettime(CLOCK_MONOTONIC, &now);
		past(&now, &start_time, &diff);
		if (n < 0) {
			fprintf(stderr, "%s error select:%s\n", progname,
				strerror(errno));
		} else {
			if (FD_ISSET(myfd, &readfds)) {
				if (verbose >= 3)
					printf("msg received %ld.%09ld\n",
						diff.tv_sec, diff.tv_nsec);
				getmsg();
			}
			if (FD_ISSET(timerfd, &readfds)) {
				if (verbose >= 3)
					printf("timer expired %ld.%09ld\n",
						diff.tv_sec, diff.tv_nsec);
				else if (verbose)
					printf("\n");
				sendall(diff.tv_sec);
			}
		}
	} while ((unsigned long)diff.tv_sec < duration);
	timer_close();
}

int main(int argc, char **argv)
{
	extern int optind, opterr;
	extern char *optarg;
	int rc = 0, ch;
	char *slash;

	progname = (slash = strrchr(argv[0], '/')) ? slash + 1 : argv[0];
	while ((ch = getopt(argc, argv, ":d:i:t:T:v"))
	    != EOF)
		switch (ch) {
		case '?':
			fprintf(stderr, "%s: unknown option -%c\n", progname,
			    optopt);
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
		case 'i':
			ifname = optarg;
			ifindex = if_nametoindex(ifname);
			break;
		}
	if (!ifindex) {
		fprintf(stderr, "%s interface %s missing or nonexistant\n",
		    progname, ifname);
		return 2;
	}
	if (l2_init(ifname))
		return 2;
	for (; optind < argc; ++optind) {
		rc |= read_profiles(argv[optind]);
		if (verbose >= 3)
			show_evblist();
	}
	hear();
	l2_close();
	return rc;
}
