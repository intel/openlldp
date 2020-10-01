# -*- autoconf -*-

# Copyright (c) 2020 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
#
# The full GNU General Public License is included in this distribution in
# the file called "COPYING".

dnl Check for C compiler support of specific flags
AC_DEFUN([_CHECK_C_COMPILER_FLAG], [
        AC_LANG_PUSH([C])
        AC_MSG_CHECKING(for $CC support of $1)
        old_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $1"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],
          AC_MSG_RESULT(yes),
          AC_MSG_RESULT(no)
          CFLAGS="$old_CFLAGS")
        AC_LANG_POP()
])

dnl Check for the various warning flags
AC_DEFUN([OPENLLDP_CHECK_WARNINGS], [
        AC_MSG_CHECKING([checking for warnings flag])
        AC_ARG_ENABLE([warnings],
                AS_HELP_STRING([--enable-warnings],
                [Add various warning flags to the build]),,
                enable_warnings=yes)
        AM_CONDITIONAL([WARNINGS_ENABLED], [test "x$enable_warnings" = "xyes"])
        AC_SUBST([WARNINGS_ENABLED], [$enable_warnings])
        AC_MSG_RESULT($enable_warnings)

        AS_IF([ test "x$enable_warnings" = "xyes"], [
                _CHECK_C_COMPILER_FLAG([-Wall])
                _CHECK_C_COMPILER_FLAG([-Wextra])
                _CHECK_C_COMPILER_FLAG([-Wformat=2])
                ])
])

dnl Checks for whether to set -Werror
AC_DEFUN([OPENLLDP_CHECK_ERROR], [
        AC_MSG_CHECKING([checking for errors flag])
        AC_ARG_ENABLE([errors],
                AS_HELP_STRING([--enable-errors],
                [Add -Werror to build flags]),,
                enable_errors=no)
        AM_CONDITIONAL([ERRORS_ENABLED], [test "x$enable_errors" = "xyes"])
        AC_SUBST([ERRORS_ENABLED], [$enable_errors])
	AC_MSG_RESULT($enable_errors)

        AS_IF([ test "x$enable_errors" = "xyes"], [
                _CHECK_C_COMPILER_FLAG([-Werror])
                ])
])
