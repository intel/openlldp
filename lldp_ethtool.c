/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2023 NXP */

#include <errno.h>
#include <linux/ethtool_netlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>

#include "lldp.h"
#include "lldp_ethtool.h"
#include "messages.h"

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

static int ethtool_msg_mm_get_parse(struct nl_msg *nlm, void *arg)
{
	struct genlmsghdr *hdr = nlmsg_data(nlmsg_hdr(nlm));
	struct nlattr *tb[ETHTOOL_A_MM_MAX];
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

	if (tb[ETHTOOL_A_MM_TX_MIN_FRAG_SIZE])
		mm->tx_min_frag_size = nla_get_u32(tb[ETHTOOL_A_MM_TX_MIN_FRAG_SIZE]);

	if (tb[ETHTOOL_A_MM_RX_MIN_FRAG_SIZE])
		mm->rx_min_frag_size = nla_get_u32(tb[ETHTOOL_A_MM_RX_MIN_FRAG_SIZE]);

	return NL_OK;
}

static int ethtool_genl_start(int cmd, int header_type, const char *ifname,
			      struct nl_sock **sock, struct nl_msg **msg)
{
	struct nlmsghdr *hdr;
	struct nlattr *attr;
	struct nl_sock *sk;
	struct nl_msg *nlm;
	int err, family_id;

	sk = nl_socket_alloc();
	if (!sk) {
		LLDPAD_ERR("Failed to allocate netlink socket\n");
		return -ENOMEM;
	}

	err = genl_connect(sk);
	if (err) {
		LLDPAD_ERR("Failed to connect to netlink socket\n");
		goto out_free;
	}

	err = genl_ctrl_resolve(sk, ETHTOOL_GENL_NAME);
	if (err < 0) {
		LLDPAD_ERR("Failed to resolve ethtool genl family id\n");
		goto out_close;
	}

	family_id = err;

	nlm = nlmsg_alloc();
	if (!nlm) {
		LLDPAD_ERR("Failed to allocate netlink message\n");
		err = -ENOMEM;
		goto out_close;
	}

	hdr = genlmsg_put(nlm, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0,
			  NLM_F_REQUEST | NLM_F_ACK, cmd, ETHTOOL_GENL_VERSION);
	if (!hdr) {
		LLDPAD_ERR("genlmsg_put() failed\n");
		err = -EMSGSIZE;
		goto out_free_nlmsg;
	}

	attr = nla_nest_start(nlm, header_type);
	nla_put_string(nlm, ETHTOOL_A_HEADER_DEV_NAME, ifname);
	nla_nest_end(nlm, attr);

	*sock = sk;
	*msg = nlm;

	return 0;

out_free_nlmsg:
	nlmsg_free(nlm);
out_close:
	nl_close(sk);
out_free:
	nl_socket_free(sk);
	return err;
}

static void ethtool_genl_stop(struct nl_sock *sk, struct nl_msg *nlm)
{
	nlmsg_free(nlm);
	nl_close(sk);
	nl_socket_free(sk);
}

int ethtool_mm_get_state(const char *ifname, struct ethtool_mm *mm)
{
	struct nl_sock *sk;
	struct nl_msg *nlm;
	int err;

	err = ethtool_genl_start(ETHTOOL_MSG_MM_GET, ETHTOOL_A_MM_HEADER,
				 ifname, &sk, &nlm);
	if (err)
		return err;

	memset(mm, 0, sizeof(*mm));

	nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM,
			    ethtool_msg_mm_get_parse, mm);

	err = nl_send_auto(sk, nlm);
	if (err < 0) {
		LLDPAD_ERR("nl_send_auto() failed: %d\n", err);
		goto out_genl_stop;
	}

	err = nl_recvmsgs_default(sk);
	if (err < 0) {
		LLDPAD_ERR("nl_recvmsgs_default() failed: %d (%s)\n",
			   err, nl_geterror(err));
		goto out_genl_stop;
	}

	err = 0;

out_genl_stop:
	ethtool_genl_stop(sk, nlm);
	return err;
}

int ethtool_mm_change_tx_enabled(const char *ifname, bool enabled, bool verify,
				 u32 verify_time)
{
	struct nl_sock *sk;
	struct nl_msg *nlm;
	int err;

	err = ethtool_genl_start(ETHTOOL_MSG_MM_SET, ETHTOOL_A_MM_HEADER,
				 ifname, &sk, &nlm);
	if (err)
		return err;

	nla_put_u8(nlm, ETHTOOL_A_MM_TX_ENABLED, enabled);
	nla_put_u8(nlm, ETHTOOL_A_MM_VERIFY_ENABLED, verify);
	nla_put_u32(nlm, ETHTOOL_A_MM_VERIFY_TIME, verify_time);

	nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM,
			    ethtool_nomsg_reply_cb, NULL);

	err = nl_send_auto(sk, nlm);
	if (err < 0) {
		LLDPAD_ERR("nl_send_auto() failed: %d\n", err);
		goto out_genl_stop;
	}

	err = nl_recvmsgs_default(sk);
	if (err < 0) {
		LLDPAD_ERR("nl_recvmsgs_default() failed: %d (%s)\n",
			   err, nl_geterror(err));
		goto out_genl_stop;
	}

	err = 0;

out_genl_stop:
	ethtool_genl_stop(sk, nlm);
	return err;
}

int ethtool_mm_change_pmac_enabled(const char *ifname, bool enabled)
{
	struct nl_sock *sk;
	struct nl_msg *nlm;
	int err;

	err = ethtool_genl_start(ETHTOOL_MSG_MM_SET, ETHTOOL_A_MM_HEADER,
				 ifname, &sk, &nlm);
	if (err)
		return err;

	nla_put_u8(nlm, ETHTOOL_A_MM_PMAC_ENABLED, enabled);

	nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM,
			    ethtool_nomsg_reply_cb, NULL);

	err = nl_send_auto(sk, nlm);
	if (err < 0) {
		LLDPAD_ERR("nl_send_auto() failed: %d\n", err);
		goto out_genl_stop;
	}

	err = nl_recvmsgs_default(sk);
	if (err < 0) {
		LLDPAD_ERR("nl_recvmsgs_default() failed: %d (%s)\n",
			   err, nl_geterror(err));
		goto out_genl_stop;
	}

	err = 0;

out_genl_stop:
	ethtool_genl_stop(sk, nlm);
	return err;
}

int ethtool_mm_change_tx_min_frag_size(const char *ifname, u32 min_frag_size)
{
	struct nl_sock *sk;
	struct nl_msg *nlm;
	int err;

	err = ethtool_genl_start(ETHTOOL_MSG_MM_SET, ETHTOOL_A_MM_HEADER,
				 ifname, &sk, &nlm);
	if (err)
		return err;

	nla_put_u32(nlm, ETHTOOL_A_MM_TX_MIN_FRAG_SIZE, min_frag_size);

	nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM,
			    ethtool_nomsg_reply_cb, NULL);

	err = nl_send_auto(sk, nlm);
	if (err < 0) {
		LLDPAD_ERR("nl_send_auto() failed: %d\n", err);
		goto out_genl_stop;
	}

	err = nl_recvmsgs_default(sk);
	if (err < 0) {
		LLDPAD_ERR("nl_recvmsgs_default() failed: %d (%s)\n",
			   err, nl_geterror(err));
		goto out_genl_stop;
	}

	err = 0;

out_genl_stop:
	ethtool_genl_stop(sk, nlm);
	return err;
}
