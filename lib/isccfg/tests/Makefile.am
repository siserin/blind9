AM_CPPFLAGS = \
	-include $(top_builddir)/config.h	\
	-I../../isc/unix/include		\
	-I../../isc/pthreads/include		\
	-I../../isc/include			\
	-I../../dns/include			\
	-I../../isccfg/include			\
	-DTESTS=\"$(abs_srcdir)\"		\
	-DNAMED_PLUGINDIR=\"$(libdir)/named\"	\
	$(OPENSSL_CFLAGS)			\
	$(JSON_C_CFLAGS)			\
	$(CMOCKA_CFLAGS)

LDADD = \
	../../libisc.la	\
	../../libdns.la \
	../../libisccfg.la \
	$(OPENSSL_LIBS)	\
	$(CMOCKA_LIBS)

check_PROGRAMS = \
	parser_test

TESTS = $(check_PROGRAMS)
