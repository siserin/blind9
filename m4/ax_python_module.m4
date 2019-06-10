# AX_PYTHON_MODULE(PROG, MODNAME, [ACTION-IF-TRUE], [ACTION-IF-FALSE])
# --------------------------------------------------------------------
# Run ACTION-IF-TRUE if the Python interpreter PROG has module MODNAME.
# Run ACTION-IF-FALSE otherwise (or fail if not defined).
#
# DESCRIPTION
#
#   Checks for Python module.
#
#   If fatal is non-empty then absence of a module will trigger an error.
#
# LICENSE
#
#   Copyright (c) 2019 Internet Systems Consortium.
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

AC_DEFUN([AX_PYTHON_MODULE],
 [AC_CACHE_CHECK([for a Python module: $2],
   [AS_TR_SH(ax_cv_pymod_$2)],
   [prog="import $2"
    AS_IF([AM_RUN_LOG([$1 -c "$prog"])],
	[AS_TR_SH(ax_cv_pymod_$2)=yes],
	[AS_TR_SH(ax_cv_pymod_$2)=no])
   ])
  AS_IF([test "AS_TR_SH($ax_cv_pymod_$2)" = "yes"],
	[AS_TR_CPP(HAVE_PYMOD_$2)=yes
	 $3
	],
	[AS_TR_CPP(HAVE_PYMOD_$2)=no
	 m4_default([$4], [AC_MSG_ERROR([failed·to·find·required·Python module $2])])
	])
 ])
