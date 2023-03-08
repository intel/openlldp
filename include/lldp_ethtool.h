#ifndef _LLDP_ETHTOOL_H
#define _LLDP_ETHTOOL_H

#include <errno.h>
#include <linux/types.h>
#include <stdbool.h>

struct ethtool_sock;

struct ethtool_sock *ethtool_sock_create(void);
void ethtool_sock_destroy(struct ethtool_sock *sk);

struct ethtool_mm {
	bool tx_enabled;
	bool tx_active;
	bool pmac_enabled;
	bool verify_enabled;
	__u8 verify_status;
	__u32 verify_time;
	__u32 max_verify_time;
	__u32 tx_min_frag_size;
	__u32 rx_min_frag_size;
};

int ethtool_mm_get_state(struct ethtool_sock *sk, const char *ifname,
			 struct ethtool_mm *mm);
int ethtool_mm_change_tx_enabled(struct ethtool_sock *sk, const char *ifname,
				 bool enabled, bool verify, u32 verify_time);
int ethtool_mm_change_pmac_enabled(struct ethtool_sock *sk, const char *ifname,
				   bool enabled);
int ethtool_mm_change_tx_min_frag_size(struct ethtool_sock *sk,
				       const char *ifname, u32 min_frag_size);

/* Translate an advertised additional fragment size into a minimum fragment
 * size in octets to pass to the kernel.
 */
static inline int ethtool_mm_frag_size_add_to_min(int add_frag_size)
{
	return 64 * (1 + add_frag_size) - 4;
}

/* Translate the minimum RX fragment size requested by the kernel into an
 * additional fragment size to advertise, that covers at least that value.
 */
static inline int ethtool_mm_frag_size_min_to_add(int min_frag_size)
{
	int add_frag_size, m;

	for (add_frag_size = 0; add_frag_size < 4; add_frag_size++) {
		m = ethtool_mm_frag_size_add_to_min(add_frag_size);
		if (m >= min_frag_size)
			return add_frag_size;
	}

	return -EINVAL;
}

#endif
