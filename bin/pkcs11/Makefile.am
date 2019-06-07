ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h	\
	-I$(top_srcdir)/lib/isc/unix/include	\
	-I$(top_srcdir)/lib/isc/pthreads/include\
	-I$(top_srcdir)/lib/isc/include		\
	$(OPENSSL_CFLAGS)			\
	$(JSON_C_CFLAGS) $(LIBXML2_CFLAGS)			\
	-DSYSCONFDIR=\"${sysconfdir}\"

LDADD =		\
	${top_builddir}/lib/libisc.la

bin_PROGRAMS = 			\
	pkcs11-list 		\
	pkcs11-destroy 		\
	pkcs11-keygen		\
	pkcs11-tokens
