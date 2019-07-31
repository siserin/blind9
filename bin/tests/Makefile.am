SUBDIRS = system # pkcs11

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h		\
	-I$(top_srcdir)/lib/isc/unix/include		\
	-I$(top_srcdir)/lib/isc/pthreads/include	\
	-I$(top_srcdir)/lib/isc/include			\
	-I$(top_srcdir)/lib/dns/include			\
	$(JSON_C_CFLAGS)				\
	$(LIBXML2_CFLAGS)

check_PROGRAMS =	\
	makejournal

makejournal_LDADD =			\
	$(top_builddir)/lib/libisc.la	\
	$(top_builddir)/lib/libdns.la
