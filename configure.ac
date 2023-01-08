AC_INIT([lldpad], [1.2.99], [lldp-devel@open-lldp.org])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

m4_pattern_allow([AM_PROG_AR])
AM_PROG_AR

AC_ARG_ENABLE(debug, 
	AS_HELP_STRING([--enable-debug],[compile debug programs]),
	[enable_debug=yes], [enable_debug=no])
if test "$enable_debug" = "yes" ; then
	AC_DEFINE_UNQUOTED([BUILD_DEBUG], 1, [whether debug code is enabled])
fi
AM_CONDITIONAL([BUILD_DEBUG], [test "$enable_debug" = "yes"])

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CXX
AC_PROG_LEX
AC_PROG_LIBTOOL

LT_INIT([dlopen])

if test "x$LEX" = x:
then
 AC_MSG_ERROR([no suitable flex found. Please install the 'flex' package.])
fi

dnl Begin determine the systemd use and location
PKG_CHECK_MODULES([SYSTEMD], [systemd], use_systemd=yes, use_systemd=no)

dnl Configure developer type flags
OPENLLDP_CHECK_WARNINGS
OPENLLDP_CHECK_ERROR
OPENLLDP_CHECK_UBSAN
OPENLLDP_CHECK_ASAN

dnl Set sysvinit values, if system has systemd it will be rewritten
AC_SUBST(SPEC_BUILD_REQUIRES_POST, "chkconfig")
AC_SUBST(SPEC_BUILD_REQUIRES_PREUN, "chkconfig initscripts")
AC_SUBST(SPEC_BUILD_REQUIRES_POSTUN, "initscripts")
specfile_install="%{_sysconfdir}/init.d/lldpad"
specfile_install_socket=""

if test "x$use_systemd" == xyes; then
        dir=""
        AC_ARG_WITH([systemdsystemunitdir],
                AS_HELP_STRING([--with-systemdsystem unitdir=DIR],
                 [Directory for systemd service files default from pkg-config variable systemdsystemunitdir]),
                [dir=${withval}],
                [dir="$($PKG_CONFIG --variable=systemdsystemunitdir systemd)"])

	systemdsystemunitdir=${dir}
	AC_SUBST(SYSTEMD_SYSTEM_UNIT_DIR, [$systemdsystemunitdir])
	specfile_install="$systemdsystemunitdir/lldpad.service"	
	specfile_install_socket="$systemdsystemunitdir/lldpad.socket"

	AC_SUBST(SPEC_BUILD_REQUIRES_POST, "systemd")
	AC_SUBST(SPEC_BUILD_REQUIRES_PREUN, "systemd")
	AC_SUBST(SPEC_BUILD_REQUIRES_POSTUN, "systemd")
fi

AM_CONDITIONAL(SYSTEMD_SYSTEM, test "x$use_systemd" == xyes)
AC_SUBST(SPEC_FILE_LLDPAD_SERVICE, $specfile_install)
AC_SUBST(SPEC_FILE_LLDPAD_SOCKET, $specfile_install_socket)
dnl End systemd stuff

PKG_CHECK_MODULES([LIBCONFIG], [libconfig >= 1.3.2])
PKG_CHECK_MODULES([LIBNL], [libnl-3.0 >= 3.2])
PKG_CHECK_MODULES([LIBNL_GENL], [libnl-genl-3.0 >= 3.2])

AC_SUBST(LIBNL_CFLAGS)
AC_SUBST(LIBNL_LIBS)

AC_SUBST(LIBNL_GENL_CFLAGS)
AC_SUBST(LIBNL_GENL_LIBS)

AC_CHECK_LIB(nl3, rtnl_link_get_by_name)

AC_CHECK_FUNCS([alarm])
AC_CHECK_FUNCS([gettimeofday])
AC_CHECK_FUNCS([inet_ntoa])
AC_CHECK_FUNCS([localtime_r])
AC_CHECK_FUNCS([memmove])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([mkdir])
AC_CHECK_FUNCS([rmdir])
AC_CHECK_FUNCS([select])
AC_CHECK_FUNCS([socket])
AC_CHECK_FUNCS([strcasecmp])
AC_CHECK_FUNCS([strchr])
AC_CHECK_FUNCS([strdup])
AC_CHECK_FUNCS([strerror])
AC_CHECK_FUNCS([strncasecmp])
AC_CHECK_FUNCS([strpbrk])
AC_CHECK_FUNCS([strrchr])
AC_CHECK_FUNCS([strstr])
AC_CHECK_FUNCS([strtol])
AC_CHECK_FUNCS([strtoul])
AC_CHECK_FUNCS([uname])

AC_CHECK_HEADER([libconfig.h], ,[AC_MSG_ERROR(
[Could not find libconfig.h. Try installing libconfig-devel])]
)
AC_CHECK_HEADER([readline/readline.h], , [AC_MSG_ERROR(
[Could not find readline.h. Try installing readline-devel])]
)
AC_CHECK_HEADER([readline/history.h], , [AC_MSG_ERROR(
[Could not find history.h. Try installing readline-devel])]
)

AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([dlfcn.h])
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([limits.h])
AC_CHECK_HEADERS([netdb.h])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([sys/file.h])
AC_CHECK_HEADERS([sys/ioctl.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_HEADERS([syslog.h])

AC_C_INLINE
AC_FUNC_CHOWN
AC_FUNC_REALLOC
AC_HEADER_STDBOOL
AC_PREREQ
AC_PROG_INSTALL
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

AC_CONFIG_FILES([Makefile include/version.h lldpad.spec lldpad.pc liblldp_clif.pc])
AC_CONFIG_MACRO_DIR([m4])
AC_OUTPUT
