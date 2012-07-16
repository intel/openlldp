# target programs to be installed in ${sbindir}
sbin_PROGRAMS = lldpad dcbtool lldptool

# package nltest and vdptest, but do not install it anywhere
if BUILD_DEBUG
noinst_PROGRAMS = nltest vdptest
endif

# look for header files in the include directory
# pass the value of ${sysconfdir} to the C pre-processor as SYSCONFDIR
AM_CPPFLAGS = -I${srcdir}/include -DSYSCONFDIR="\"${sysconfdir}\"" \
	-D_FORTIFY_SOURCE=2

ACLOCAL_AMFLAGS = -I m4

parse_cli.o: CFLAGS+=-U_FORTIFY_SOURCE -Wno-error

## system requires a shared libconfig
AM_CFLAGS = -Wall -Werror -Wextra -Wformat=2 $(LIBCONFIG_CFLAGS)
AM_LDFLAGS = $(LIBCONFIG_LIBS)

## header files to be installed, for programs using the client interface to lldpad 
lldpad_includedir= ${includedir}/lldpad

lldpad_include_HEADERS = include/dcb_types.h \
include/clif.h include/lldp_dcbx_cmds.h \
include/lldpad.h include/lldp_mand_cmds.h \
include/clif_msgs.h include/lldp_basman_cmds.h include/lldp_8023_cmds.h \
include/lldp_med_cmds.h include/lldp_util.h \
include/lldp_evb_cmds.h include/lldp_vdp_cmds.h include/lldp_8021qaz_cmds.h \
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
include/lldp_vdp_clif.h include/lldp_8021qaz_clif.h \
include/lldp_orgspec_clif.h include/lldp_cisco_clif.h \
include/lldptool.h include/lldp_rtnl.h include/dcbtool.h include/lldp_dcbx_cfg.h

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
lldp_evb_cmds.c lldp_evb.c include/lldp_evb.h lldp_vdp_cmds.c lldp_vdp_utils.c \
include/lldp_vdp_cmds.h \
ecp/ecp.c ecp/ecp_tx.c ecp/ecp_rx.c ecp/ecp.h lldp_vdp.c include/lldp_vdp.h \
lldp_tlv.c include/lldp_tlv.h \
lldp_basman.c include/lldp_basman.h \
lldp_med.c include/lldp_med.h \
lldp_8023.c include/lldp_8023.h \
lldp_8021qaz.c include/lldp_8021qaz.h \
lldp_8021qaz_cmds.c include/lldp_8021qaz_cmds.h

lib_LTLIBRARIES = liblldp_clif.la
liblldp_clif_la_LDFLAGS = -version-info 1:0:0
liblldp_clif_includedir = ${srcdir}/include
liblldp_clif_la_SOURCES = clif.c

dcbtool_SOURCES = dcbtool.c dcbtool_cmds.c parse_cli.l \
weak_readline.c $(lldpad_include_HEADERS) $(noinst_HEADERS)
dcbtool_LDADD = ${srcdir}/liblldp_clif.la
dcbtool_LDFLAGS = -ldl -llldp_clif

lldptool_SOURCES = lldptool.c lldptool_cmds.c lldp_rtnl.c \
		   lldp_mand_clif.c lldp_basman_clif.c lldp_med_clif.c \
		   lldp_8023_clif.c lldp_dcbx_clif.c lldp_util.c \
		   lldp_8021qaz_clif.c lldp_evb_clif.c lldp_vdp_clif.c \
		   lldp_orgspec_clif.c lldp_cisco_clif.c \
		   weak_readline.c $(lldpad_include_HEADERS) $(noinst_HEADERS)
lldptool_LDADD = ${srcdir}/liblldp_clif.la
lldptool_LDFLAGS = -ldl -llldp_clif

if BUILD_DEBUG
nltest_SOURCES = test/nltest.c test/nltest.h
vdptest_SOURCES = test/vdptest.c
endif

## man pages
dist_man_MANS = docs/lldpad.8 docs/dcbtool.8 docs/lldptool.8 \
		docs/lldptool-ets.8 docs/lldptool-pfc.8 docs/lldptool-app.8 \
		docs/lldptool-evb.8 docs/lldptool-vdp.8 docs/lldptool-med.8

## force the creation of an empty configuration directory at install time
lldpadconfigdir = /var/lib/lldpad
lldpadconfig_DATA =

## pkg-config data file, for client interface software to find headers
pkgconfigdir = ${libdir}/pkgconfig
pkgconfig_DATA = lldpad.pc liblldp_clif.pc

## put a spec file and documentation in the distribution archive
dist_noinst_DATA = lldpad.spec README COPYING ChangeLog

## lldpad.init is listed here because it gets installed from install-data-local
dist_noinst_SCRIPTS = lldpad.init

## special hooks to handle the init script
install-data-local: lldpad.init
	$(MKDIR_P) $(DESTDIR)/etc/init.d
	$(INSTALL_SCRIPT) lldpad.init $(DESTDIR)/etc/init.d/lldpad

BASH_COMPLETION_DIR=/etc/bash_completion.d/

install-data-hook:
	/sbin/chkconfig --add lldpad || true
	## provide support for bash completion
	$(MKDIR_P) $(DESTDIR)/$(BASH_COMPLETION_DIR)
	$(INSTALL_SCRIPT) ${srcdir}/contrib/bash_completion/* $(DESTDIR)/$(BASH_COMPLETION_DIR)

uninstall-local:
	/sbin/chkconfig --del lldpad || true
	rm -f '$(DESTDIR)/etc/init.d/lldpad'
	rm -f '$(includedir)/dcbd/clif_cmds.h'
	rm -f '$(includedir)/dcbd'

