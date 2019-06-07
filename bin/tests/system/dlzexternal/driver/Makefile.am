ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h	\
	-I$(top_srcdir)/lib/isc/unix/include	\
	-I$(top_srcdir)/lib/isc/pthreads/include\
	-I$(top_srcdir)/lib/isc/include		\
	-I$(top_srcdir)/lib/dns/include	\
	$(JSON_C_CFLAGS) $(LIBXML2_CFLAGS)

dlzexternal_LTLIBRARIES = dlzexternal.la
dlzexternaldir = ${abs_builddir}

dlzexternal_la_SOURCES =	\
	driver.c

dlzexternal_la_LDFLAGS = -avoid-version -module -shared -export-dynamic
