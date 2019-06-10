do_subst = $(SED) \
	       -e 's,[@]PYTHON[@],$(PYTHON),g' \
	       -e 's,[@]prefix[@],$(prefix),g' \
	       -e 's,[@]pythondir[@],$(pythondir),g' \
	       -e 's,[@]sysconfdir[@],$(sysconfdir),g'

EXTRA_DIST =			\
	isc/utils.py		\
	dnssec-checkds.py	\
	dnssec-coverage.py	\
	dnssec-keymgr.py

BUILT_SOURCES =		\
	isc/utils.py		\
	isc/parsetab.py

isc/utils.py: isc/utils.py.in
	$(do_subst) < $< > $@

isc/parsetab.py: isc/policy.py
	$(PYTHON) isc/policy.py parse /dev/null >/dev/null
	PYTHONPATH=$(abs_builddir)/isc $(PYTHON) -m parsetab

dnssec-checkds: dnssec-checkds.py.in
	$(do_subst) < $< > $@
	chmod +x $@

dnssec-coverage: dnssec-coverage.py.in
	$(do_subst) < $< > $@
	chmod +x $@

dnssec-keymgr: dnssec-keymgr.py.in
	$(do_subst) < $< > $@
	chmod +x $@

python_PYTHON =		\
	isc/__init__.py	\
	isc/checkds.py		\
	isc/coverage.py	\
	isc/dnskey.py		\
	isc/eventlist.py	\
	isc/keydict.py		\
	isc/keyevent.py	\
	isc/keymgr.py		\
	isc/keyseries.py	\
	isc/keyzone.py		\
	isc/parsetab.py	\
	isc/policy.py		\
	isc/rndc.py		\
	isc/utils.py

bin_SCRIPTS =			\
	dnssec-checkds		\
	dnssec-coverage	\
	dnssec-keymgr

CLEANFILES =			\
	$(BUILT_SOURCES)	\
	$(bin_SCRIPTS)
