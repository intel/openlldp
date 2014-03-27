#!/bin/bash
#
# Thomas Richter, DCN Linux Technology Center, IBM Research, Germany 29-Apr-2013
#
# Setup a lldpad test environment with 2 virtual ethernet device in 2 different
# network name spaces.
# lldpad runs in default name space and the qbg22sim runs in the newly created
# bridge_ns name space. veth0 is in the default net name space where as
# interface veth2 is in the bridge_ns name space
#

# Check if the name space already exists. Also check if the interface veth0
# has been defined.
if ip netns list | fgrep -qi bridge_ns
then
	if ip link | fgrep -qi veth0
	then
		if ip netns exec bridge_ns ip link | fgrep -qi veth2
		then
			exit 0		# veth0 and veth2 exists
		else
			echo interface veth2 missing
			ip netns del bridge_ns
		fi
	else
		ip netns del bridge_ns
	fi
fi

# create veth pair(veth0, veth2)
# with this mac address on veth0 e6:f1:20:5a:b0:e6 for evb testing
ip link add veth0 address e6:f1:20:5a:b0:e6 type veth peer name veth2
ip link set veth0 up
ip addr add 50.0.0.1/24 dev veth0

# create a new network namespace bridge_ns, bring up veth0 and assign an ip addr
ip netns add bridge_ns

# move veth2 to bridge_ns
ip link set veth2 netns bridge_ns
ip netns exec bridge_ns ip link set veth2 up
ip netns exec bridge_ns ip addr add 50.0.0.2/24 dev veth2

# exec bash in bridge_ns
# ip netns exec bridge_ns bash
