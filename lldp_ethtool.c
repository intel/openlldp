/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2023 NXP */

#include <errno.h>
#include <linux/ethtool_netlink.h>
#include <linux/netlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>

#include "lldp.h"
#include "lldp_ethtool.h"
#include "messages.h"

struct ethtool_sock {
	struct nl_sock *nlsk;
	int family_id;
};

struct ethtool_sock *ethtool_sock_create(void)
{
	struct ethtool_sock *sk;
	int err, opt;

	sk = calloc(1, sizeof(*sk));
	if (!sk) {
		LLDPAD_ERR("Failed to allocate ethtool socket\n");
		return NULL;
	}

	sk->nlsk = nl_socket_alloc();
	if (!sk->nlsk) {
		LLDPAD_ERR("Failed to allocate netlink socket\n");
		goto out_free_sk;
	}

	err = genl_connect(sk->nlsk);
	if (err) {
		LLDPAD_ERR("Failed to connect to netlink socket: %d\n", err);
		goto out_free_nls;
	}

	err = genl_ctrl_resolve(sk->nlsk, ETHTOOL_GENL_NAME);
	if (err < 0) {
		LLDPAD_ERR("Failed to resolve ethtool genl family id: %d\n",
			   err);
		goto out_close;
	}

	sk->family_id = err;

	/* try to set NETLINK_EXT_ACK to 1, ignoring errors */
	opt = 1;
	setsockopt(nl_socket_get_fd(sk->nlsk), SOL_NETLINK,
		   NETLINK_EXT_ACK, &opt, sizeof(opt));

	/* try to set NETLINK_CAP_ACK to 1, ignoring errors */
	opt = 1;
	setsockopt(nl_socket_get_fd(sk->nlsk), SOL_NETLINK,
		   NETLINK_CAP_ACK, &opt, sizeof(opt));

	return sk;

out_close:
	nl_close(sk->nlsk);
out_free_nls:
	nl_socket_free(sk->nlsk);
out_free_sk:
	free(sk);
	return NULL;
}

void ethtool_sock_destroy(struct ethtool_sock *sk)
{
	nl_close(sk->nlsk);
	nl_socket_free(sk->nlsk);
	free(sk);
}

static struct nl_msg *ethtool_nlmsg_create(struct ethtool_sock *sk, int cmd,
					   int header_type, const char *ifname)
{
	struct nlmsghdr *hdr;
	struct nlattr *attr;
	struct nl_msg *nlm;

	nlm = nlmsg_alloc();
	if (!nlm) {
		LLDPAD_ERR("Failed to allocate netlink message\n");
		return NULL;
	}

	hdr = genlmsg_put(nlm, NL_AUTO_PORT, NL_AUTO_SEQ, sk->family_id, 0,
			  NLM_F_REQUEST | NLM_F_ACK, cmd, ETHTOOL_GENL_VERSION);
	if (!hdr) {
		LLDPAD_ERR("genlmsg_put() failed\n");
		goto out_free_nlmsg;
	}

	attr = nla_nest_start(nlm, header_type);
	nla_put_string(nlm, ETHTOOL_A_HEADER_DEV_NAME, ifname);
	nla_nest_end(nlm, attr);

	return nlm;

out_free_nlmsg:
	nlmsg_free(nlm);
	return NULL;
}

static struct nla_policy ethtool_mm_genl_policy[ETHTOOL_A_MM_MAX + 1] = {
	[ETHTOOL_A_MM_UNSPEC]		= { .type = NLA_UNSPEC },
	[ETHTOOL_A_MM_HEADER]		= { .type = NLA_NESTED },
	[ETHTOOL_A_MM_VERIFY_STATUS]	= { .type = NLA_U8 },
	[ETHTOOL_A_MM_VERIFY_ENABLED]	= { .type = NLA_U8 },
	[ETHTOOL_A_MM_VERIFY_TIME]	= { .type = NLA_U32 },
	[ETHTOOL_A_MM_MAX_VERIFY_TIME]	= { .type = NLA_U32 },
	[ETHTOOL_A_MM_TX_ENABLED]	= { .type = NLA_U8 },
	[ETHTOOL_A_MM_TX_ACTIVE]	= { .type = NLA_U8 },
	[ETHTOOL_A_MM_PMAC_ENABLED]	= { .type = NLA_U8 },
	[ETHTOOL_A_MM_TX_MIN_FRAG_SIZE]	= { .type = NLA_U32 },
	[ETHTOOL_A_MM_RX_MIN_FRAG_SIZE]	= { .type = NLA_U32 },
	[ETHTOOL_A_MM_STATS]		= { .type = NLA_NESTED },
};

/* Reply callback for requests where no reply is expected (e.g. most "set" type
 * commands)
 */
static int ethtool_nomsg_reply_cb(struct nl_msg *nlm, UNUSED void *arg)
{
	struct nlmsghdr *nlhdr = nlmsg_hdr(nlm);
	struct genlmsghdr *ghdr = nlmsg_data(nlhdr);

	LLDPAD_ERR("received unexpected message: len=%u type=%u cmd=%u\n",
		   nlhdr->nlmsg_len, nlhdr->nlmsg_type, ghdr->cmd);

	return NL_STOP;
}

static int error_handler(UNUSED struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *) err - 1;
	int ack_len = sizeof(*nlh) + sizeof(int) + sizeof(*nlh);
	struct nlattr *tb[NLMSGERR_ATTR_MAX + 1];
	int len = nlh->nlmsg_len;
	struct nlattr *attrs;
	int *ret = arg;

	*ret = err->error;

	if (!(nlh->nlmsg_flags & NLM_F_ACK_TLVS))
		return NL_SKIP;

	if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
		ack_len += err->msg.nlmsg_len - sizeof(*nlh);

	if (len <= ack_len)
		return NL_STOP;

	attrs = (void *) ((unsigned char *) nlh + ack_len);
	len -= ack_len;

	nla_parse(tb, NLMSGERR_ATTR_MAX, attrs, len, NULL);
	if (tb[NLMSGERR_ATTR_MSG]) {
		len = strnlen((char *) nla_data(tb[NLMSGERR_ATTR_MSG]),
			      nla_len(tb[NLMSGERR_ATTR_MSG]));
		LLDPAD_ERR("ethtool: kernel reports: %*s\n",
			   len, (char *) nla_data(tb[NLMSGERR_ATTR_MSG]));
	}

	return NL_SKIP;
}

static int ack_handler(UNUSED struct nl_msg *msg, void *arg)
{
	int *err = arg;
	*err = 0;
	return NL_STOP;
}

static int ethtool_msg_mm_get_parse(struct nl_msg *nlm, void *arg)
{
	struct genlmsghdr *hdr = nlmsg_data(nlmsg_hdr(nlm));
	struct nlattr *tb[ETHTOOL_A_MM_MAX + 1];
	struct ethtool_mm *mm = arg;

	if (nla_parse(tb, ETHTOOL_A_MM_MAX, genlmsg_attrdata(hdr, 0),
		      genlmsg_attrlen(hdr, 0), ethtool_mm_genl_policy)) {
		printf("nla_parse() failed\n");
		return NL_STOP;
	}

	if (tb[ETHTOOL_A_MM_VERIFY_STATUS])
		mm->verify_status = nla_get_u8(tb[ETHTOOL_A_MM_VERIFY_STATUS]);

	if (tb[ETHTOOL_A_MM_VERIFY_TIME])
		mm->verify_time = nla_get_u32(tb[ETHTOOL_A_MM_VERIFY_TIME]);

	if (tb[ETHTOOL_A_MM_MAX_VERIFY_TIME])
		mm->max_verify_time =
			nla_get_u32(tb[ETHTOOL_A_MM_MAX_VERIFY_TIME]);

	if (tb[ETHTOOL_A_MM_TX_ENABLED])
		mm->tx_enabled = nla_get_u8(tb[ETHTOOL_A_MM_TX_ENABLED]);

	if (tb[ETHTOOL_A_MM_TX_ACTIVE])
		mm->tx_active = nla_get_u8(tb[ETHTOOL_A_MM_TX_ACTIVE]);

	if (tb[ETHTOOL_A_MM_PMAC_ENABLED])
		mm->pmac_enabled = nla_get_u8(tb[ETHTOOL_A_MM_PMAC_ENABLED]);

	if (tb[ETHTOOL_A_MM_VERIFY_ENABLED])
		mm->verify_enabled = nla_get_u8(tb[ETHTOOL_A_MM_VERIFY_ENABLED]);

	if (tb[ETHTOOL_A_MM_TX_MIN_FRAG_SIZE])
		mm->tx_min_frag_size = nla_get_u32(tb[ETHTOOL_A_MM_TX_MIN_FRAG_SIZE]);

	if (tb[ETHTOOL_A_MM_RX_MIN_FRAG_SIZE])
		mm->rx_min_frag_size = nla_get_u32(tb[ETHTOOL_A_MM_RX_MIN_FRAG_SIZE]);

	return NL_OK;
}

static int ethtool_genl_txrx(struct ethtool_sock *sk, struct nl_msg *nlm,
			     nl_recvmsg_msg_cb_t func, void *arg)
{
	struct nl_cb *cb = NULL, *orig;
	int err, ret;

	orig = nl_socket_get_cb(sk->nlsk);
	if (!orig) {
		LLDPAD_ERR("nl_socket_get_cb() failed\n");
		return -ENOMEM;
	}

	cb = nl_cb_clone(orig);
	if (!cb) {
		LLDPAD_ERR("nl_cb_clone() failed\n");
		err = -ENOMEM;
		goto err_put_orig;
	}

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, func, arg);
	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

	err = nl_send_auto(sk->nlsk, nlm);
	if (err < 0) {
		LLDPAD_ERR("nl_send_auto() failed: %d (%s)\n", err,
			   nl_geterror(err));
		goto err_put_cb;
	}

	err = 1;

	/* Wait until the ack_handler() has executed */
	while (err > 0) {
		ret = nl_recvmsgs(sk->nlsk, cb);
		if (ret < 0) {
			LLDPAD_ERR("nl_recvmsgs_default() failed: %d (%s)\n",
				   ret, nl_geterror(ret));
			err = ret;
			goto err_put_cb;
		}
	}

	nl_cb_put(cb);
	nl_cb_put(orig);

	return 0;

err_put_cb:
	nl_cb_put(cb);
err_put_orig:
	nl_cb_put(orig);
	return err;
}

int ethtool_mm_get_state(struct ethtool_sock *sk, const char *ifname,
			 struct ethtool_mm *mm)
{
	struct nl_msg *nlm;
	int err;

	nlm = ethtool_nlmsg_create(sk, ETHTOOL_MSG_MM_GET, ETHTOOL_A_MM_HEADER,
				   ifname);
	if (!nlm)
		return -ENOMEM;

	memset(mm, 0, sizeof(*mm));

	err = ethtool_genl_txrx(sk, nlm, ethtool_msg_mm_get_parse, mm);
	nlmsg_free(nlm);

	return err;
}

int ethtool_mm_change_tx_enabled(struct ethtool_sock *sk, const char *ifname,
				 bool enabled, bool verify, u32 verify_time)
{
	struct nl_msg *nlm;
	int err;

	nlm = ethtool_nlmsg_create(sk, ETHTOOL_MSG_MM_SET, ETHTOOL_A_MM_HEADER,
				   ifname);
	if (!nlm)
		return -ENOMEM;

	nla_put_u8(nlm, ETHTOOL_A_MM_TX_ENABLED, enabled);
	nla_put_u8(nlm, ETHTOOL_A_MM_VERIFY_ENABLED, verify);
	nla_put_u32(nlm, ETHTOOL_A_MM_VERIFY_TIME, verify_time);

	err = ethtool_genl_txrx(sk, nlm, ethtool_nomsg_reply_cb, NULL);
	nlmsg_free(nlm);

	return err;
}

int ethtool_mm_change_pmac_enabled(struct ethtool_sock *sk, const char *ifname,
				   bool enabled)
{
	struct nl_msg *nlm;
	int err;

	nlm = ethtool_nlmsg_create(sk, ETHTOOL_MSG_MM_SET, ETHTOOL_A_MM_HEADER,
				   ifname);
	if (!nlm)
		return -ENOMEM;

	nla_put_u8(nlm, ETHTOOL_A_MM_PMAC_ENABLED, enabled);

	err = ethtool_genl_txrx(sk, nlm, ethtool_nomsg_reply_cb, NULL);
	nlmsg_free(nlm);

	return err;
}

int ethtool_mm_change_tx_min_frag_size(struct ethtool_sock *sk,
				       const char *ifname, u32 min_frag_size)
{
	struct nl_msg *nlm;
	int err;

	nlm = ethtool_nlmsg_create(sk, ETHTOOL_MSG_MM_SET, ETHTOOL_A_MM_HEADER,
				   ifname);
	if (!nlm)
		return -ENOMEM;

	nla_put_u32(nlm, ETHTOOL_A_MM_TX_MIN_FRAG_SIZE, min_frag_size);

	err = ethtool_genl_txrx(sk, nlm, ethtool_nomsg_reply_cb, NULL);
	nlmsg_free(nlm);

	return err;
}
