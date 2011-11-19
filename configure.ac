AC_INIT([lldpad], [0.9.43])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

AC_PROG_CC
AC_PROG_CXX
AC_PROG_LEX
AC_PROG_LIBTOOL

PKG_CHECK_MODULES([LIBCONFIG], [libconfig >= 1.3.2])
PKG_CHECK_MODULES([LIBNL], [libnl-1 >= 1.1])

AC_SUBST(LIBNL_CFLAGS)
AC_SUBST(LIBNL_LIBS)

AC_CHECK_LIB(nl, rtnl_link_get_by_name)

AC_CHECK_FUNCS([alarm])
AC_CHECK_FUNCS([gettimeofday])
AC_CHECK_FUNCS([inet_ntoa])
AC_CHECK_FUNCS([memmove])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([mkdir])
AC_CHECK_FUNCS([rmdir])
AC_CHECK_FUNCS([select])
AC_CHECK_FUNCS([socket])
AC_CHECK_FUNCS([strcasecmp])
AC_CHECK_FUNCS([strdup])
AC_CHECK_FUNCS([strncasecmp])
AC_CHECK_FUNCS([strtol])
AC_CHECK_FUNCS([strtoul])
AC_CHECK_FUNCS([uname])

AC_CHECK_HEADER([libconfig.h], ,[AC_MSG_ERROR(
[Could not find libconfig.h. Try installing libconfig-devel])]
)

AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([netdb.h])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([sys/file.h])
AC_CHECK_HEADERS([sys/ioctl.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([syslog.h])

AC_C_INLINE
AC_FUNC_CHOWN
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_HEADER_STDBOOL
AC_PREREQ
AC_PROG_INSTALL
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T

AC_CONFIG_FILES([Makefile include/version.h lldpad.spec lldpad.pc])
AC_CONFIG_MACRO_DIR([m4])
AC_OUTPUT
