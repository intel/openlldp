# target programs to be installed in ${sbindir}
sbin_PROGRAMS = lldpad dcbtool lldptool vdptool

check_PROGRAMS = lldp_clif_test
TESTS = $(check_PROGRAMS)

# package nltest and vdptest, but do not install it anywhere
if BUILD_DEBUG
noinst_PROGRAMS = nltest vdptest qbg22sim
endif

# look for header files in the include directory
# pass the value of ${sysconfdir} to the C pre-processor as SYSCONFDIR
AM_CPPFLAGS = -I${srcdir}/include -DSYSCONFDIR="\"${sysconfdir}\"" \
	-D_FORTIFY_SOURCE=2

ACLOCAL_AMFLAGS = -I m4

parse_cli.o: CFLAGS+=-U_FORTIFY_SOURCE -Wno-error

## system requires a shared libconfig
AM_CFLAGS = $(LIBCONFIG_CFLAGS) $(LIBNL_CFLAGS) $(LIBNL_GENL_CFLAGS)
AM_LDFLAGS = $(LIBCONFIG_LIBS) $(LIBNL_LIBS) $(LIBNL_GENL_LIBS) -lrt

## header files to be installed, for programs using the client interface to lldpad 
lldpad_includedir= ${includedir}/lldpad

lldpad_include_HEADERS = include/dcb_types.h \
include/clif.h include/lldp_dcbx_cmds.h \
include/lldpad.h include/lldp_mand_cmds.h \
include/clif_msgs.h include/lldp_basman_cmds.h include/lldp_8023_cmds.h \
include/lldp_med_cmds.h include/lldp_util.h \
include/lldp_evb_cmds.h include/qbg_vdp_cmds.h include/lldp_8021qaz_cmds.h \
include/clif_sock.h include/linux/dcbnl.h \
include/linux/netlink.h include/linux/rtnetlink.h \
include/lldpad_status.h

noinst_HEADERS = include/config.h include/ctrl_iface.h \
include/dcb_driver_interface.h \
include/dcb_events.h include/dcb_persist_store.h include/dcb_protocol.h \
include/dcb_rule_chk.h include/lldp_dcbx_nl.h include/eloop.h \
include/lldpad_shm.h include/event_iface.h include/messages.h \
include/parse_cli.h include/version.h include/lldptool_cli.h include/list.h \
include/lldp_mand_clif.h include/lldp_basman_clif.h include/lldp_med_clif.h \
include/lldp_8023_clif.h include/lldp_dcbx_clif.h include/lldp_evb_clif.h \
include/lldp_evb22_clif.h include/qbg_vdp_clif.h include/qbg_vdpnl.h \
include/qbg_vdp22_clif.h include/lldp_8021qaz_clif.h \
include/lldp_orgspec_clif.h include/lldp_cisco_clif.h \
include/lldptool.h include/lldp_rtnl.h include/dcbtool.h include/lldp_dcbx_cfg.h \
include/qbg_vdp22_cmds.h include/qbg_vdp22_clif.h \
include/linux/ethtool.h include/linux/if_bonding.h include/linux/if_bridge.h \
include/linux/if.h include/linux/if_link.h include/linux/if_vlan.h

lldpad_SOURCES = lldpad.c config.c lldp_dcbx_nl.c ctrl_iface.c \
event_iface.c eloop.c lldp_dcbx_cmds.c log.c lldpad_shm.c \
dcb_protocol.c dcb_rule_chk.c  list.c lldp_rtnl.c \
$(lldpad_include_HEADERS) $(noinst_HEADERS) \
lldp/ports.c lldp/agent.c lldp/l2_packet_linux.c lldp/tx.c \
lldp/rx.c lldp/agent.h lldp/l2_packet.h lldp/mibdata.h lldp/ports.h \
lldp/states.h include/lldp.h include/lldp_mod.h \
lldp_dcbx.c include/lldp_dcbx.h tlv_dcbx.c include/tlv_dcbx.h \
lldp_dcbx_cfg.c include/lldp_dcbx_cfg.h lldp_util.c \
lldp_mand.c include/lldp_mand.h \
lldp_mand_cmds.c lldp_basman_cmds.c lldp_8023_cmds.c lldp_med_cmds.c \
lldp_evb_cmds.c lldp_evb.c include/lldp_evb.h qbg/vdp_cmds.c \
include/qbg_vdp_cmds.h \
include/qbg_ecp.h include/qbg_utils.h qbg/ecp.c qbg_utils.c \
qbg/vdp.c include/qbg_vdp.h \
lldp_ethtool.c include/lldp_ethtool.h \
lldp_tlv.c include/lldp_tlv.h \
lldp_basman.c include/lldp_basman.h \
lldp_med.c include/lldp_med.h \
lldp_8023.c include/lldp_8023.h \
lldp_8021qaz.c include/lldp_8021qaz.h \
lldp_8021qaz_cmds.c include/lldp_8021qaz_cmds.h \
include/lldp_evb22.h lldp_evb22.c lldp_evb22_cmds.c \
include/qbg22.h include/qbg_ecp22.h qbg/ecp22.c \
include/qbg_vdp22.h qbg/vdp22.c qbg/vdpnl.c qbg/vdp22sm.c qbg/vdp22br.c \
include/qbg_vdp22def.h qbg/vdp22_cmds.c qbg/vdp_ascii.c \
include/qbg_vdp22_oui.h qbg/vdp22_oui.c include/vdp_cisco.h \
qbg/vdp22cisco_oui.c

lib_LTLIBRARIES = liblldp_clif.la
liblldp_clif_la_LDFLAGS = -version-info 1:0:0
liblldp_clif_includedir = ${srcdir}/include
liblldp_clif_la_SOURCES = clif.c

vdptool_SOURCES = vdptool.c lldp_util.c qbg/vdp22_clif.c vdptool_cisco_oui.c
vdptool_LDADD = liblldp_clif.la
vdptool_LDFLAGS = -llldp_clif $(LIBNL_LIBS)

dcbtool_SOURCES = dcbtool.c dcbtool_cmds.c parse_cli.l \
	weak_readline.c lldp_rtnl.c lldp_util.c \
	$(lldpad_include_HEADERS) $(noinst_HEADERS)

dcbtool_LDADD = liblldp_clif.la
dcbtool_LDFLAGS = -ldl -llldp_clif $(LIBNL_LIBS)

lldptool_SOURCES = lldptool.c lldptool_cmds.c lldp_rtnl.c \
		   lldp_mand_clif.c lldp_basman_clif.c lldp_med_clif.c \
		   lldp_8023_clif.c lldp_dcbx_clif.c lldp_util.c \
		   lldp_8021qaz_clif.c lldp_evb_clif.c qbg/vdp_clif.c \
		   lldp_orgspec_clif.c lldp_cisco_clif.c lldp_evb22_clif.c \
		   weak_readline.c $(lldpad_include_HEADERS) $(noinst_HEADERS)
lldptool_LDADD = liblldp_clif.la
lldptool_LDFLAGS = -ldl -llldp_clif $(LIBNL_LIBS)

if BUILD_DEBUG
nltest_SOURCES = test/nltest.c test/nltest.h
vdptest_SOURCES = test/vdptest.c
vdptest_LDFLAGS = -llldp_clif
qbg22sim_SOURCES = test/qbg22sim.c
qbg22sim_LDFLAGS = -lrt
endif

## put a spec file and documentation in the distribution archive
dist_noinst_DATA = lldpad.spec README COPYING ChangeLog lldpad.init

## man pages
dist_man_MANS = docs/lldpad.8 docs/dcbtool.8 docs/lldptool.8 \
		docs/lldptool-ets.8 docs/lldptool-pfc.8 docs/lldptool-app.8 \
		docs/lldptool-evb.8 docs/lldptool-vdp.8 docs/lldptool-med.8 \
		docs/lldptool-dcbx.8 \
		docs/lldptool-evb22.8 docs/vdptool.8 \
		docs/liblldp_clif-vdp22.3
if BUILD_DEBUG
dist_man_MANS += test/qbg22sim.1 test/vdptest.1
else
dist_noinst_DATA += test/qbg22sim.1 test/vdptest.1
endif

## force the creation of an empty configuration directory at install time
lldpadconfigdir = /var/lib/lldpad
installdirs-local:	
	$(MKDIR_P) $(DESTDIR)$(lldpadconfigdir)
install-data-hook:	installdirs-local

## pkg-config data file, for client interface software to find headers
pkgconfigdir = ${libdir}/pkgconfig
pkgconfig_DATA = lldpad.pc liblldp_clif.pc

systemdsystemunitdir = $(prefix)/lib/systemd/system
dist_systemdsystemunit_DATA = lldpad.service lldpad.socket

bashcompletiondir = $(sysconfdir)/bash_completion.d
dist_bashcompletion_DATA = contrib/bash_completion/lldpad contrib/bash_completion/lldptool

AM_DISTCHECK_CONFIGURE_FLAGS = --enable-debug

lldp_clif_test_SOURCES = test/lldp_clif_test.c lldp_basman_clif.c lldp_util.c \
	lldp_rtnl.c
lldp_clif_test_LDFLAGS = -lrt $(LIBNL_LIBS)

RPMBUILD_TOP = $(abs_top_builddir)/rpm/rpmbuild
RPMBUILD_OPT ?= --without check

# Build user-space RPMs
rpm: dist $(srcdir)/lldpad.spec
	${MKDIR_P} ${RPMBUILD_TOP}/SOURCES
	cp ${DIST_ARCHIVES} ${RPMBUILD_TOP}/SOURCES
	rpmbuild ${RPMBUILD_OPT} \
                 -D "_topdir ${RPMBUILD_TOP}" \
                 -ba $(srcdir)/lldpad.spec
