# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# http://www.sphinx-doc.org/en/master/config

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))


# -- Project information -----------------------------------------------------

project = u'BIND 9'
copyright = u'2019, Internet Systems Consortium'
author = u'Internet Systems Consortium'

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# The master toctree document.
master_doc = 'index'

# Additional documents
notes_doc = 'notes'

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'sphinx_rtd_theme'

# -- Options for LaTeX output ------------------------------------------------

latex_documents = [
    (master_doc, 'Bv9ARM.tex', u'BIND 9 Administrator Reference Manual', author, 'manual'),
    (notes_doc, 'notes.tex', u'BIND 9 Release Notes', author, 'howto'),
    ]

latex_logo = "isc-logo.pdf"

man_pages = [
	('man_arpaname', 'arpaname', 'translate IP addresses to the corresponding ARPA names', author, 1),
	('man_ddns-confgen', 'ddns-confgen', 'ddns key generation tool', author, 8),
	('man_delv', 'delv', 'DNS lookup and validation utility', author, 1),
	('man_dig', 'dig', 'DNS lookup utility', author, 1),
	('man_dnssec-cds', 'dnssec-cds', 'change DS records for a child zone based on CDS/CDNSKEY', author, 8),
	('man_dnssec-checkds', 'dnssec-checkds', 'DNSSEC delegation consistency checking tool', author, 8),
	('man_dnssec-coverage', 'dnssec-coverage', 'checks future DNSKEY coverage for a zone', author, 8),
	('man_dnssec-dsfromkey', 'dnssec-dsfromkey', 'DNSSEC DS RR generation tool', author, 8),
	('man_dnssec-importkey', 'dnssec-importkey', 'import DNSKEY records from external systems so they can be managed', author, 8),
	('man_dnssec-keyfromlabel', 'dnssec-keyfromlabel', 'DNSSEC key generation tool', author, 8),
	('man_dnssec-keygen', 'dnssec-keygen', 'DNSSEC key generation tool', author, 8),
	('man_dnssec-keymgr', 'dnssec-keymgr', 'ensures correct DNSKEY coverage for a zone based on a defined policy', author, 8),
	('man_dnssec-revoke', 'dnssec-revoke', 'set the REVOKED bit on a DNSSEC key', author, 8),
	('man_dnssec-settime', 'dnssec-settime', 'set the key timing metadata for a DNSSEC key', author, 8),
	('man_dnssec-signzone', 'dnssec-signzone', 'DNSSEC zone signing tool', author, 8),
	('man_dnssec-verify', 'dnssec-verify', 'DNSSEC zone verification tool', author, 8),
	('man_dnstap-read', 'dnstap-read', 'print dnstap data in human-readable form', author, 1),
	('man_filter-aaaa', 'filter-aaaa', 'filter AAAA in DNS responses when A is present', author, 8),
	('man_host', 'host', 'DNS lookup utility', author, 1),
	('man_mdig', 'mdig', 'DNS pipelined lookup utility', author, 1),
	('man_named-checkconf', 'named-checkconf', 'named configuration file syntax checking tool', author, 8),
	('man_named-checkzone', 'named-checkzone', 'zone file validity checking or converting tool', author, 8),
	('man_named-journalprint', 'named-journalprint', 'print zone journal in human-readable form', author, 8),
	('man_named-nzd2nzf', 'named-nzd2nzf', 'convert an NZD database to NZF text format', author, 8),
	('man_named-rrchecker', 'named-rrchecker', 'syntax checker for individual DNS resource records', author, 1),
	('man_named.conf', 'named.conf', 'configuration file for **named**', author, 5),
	('man_named', 'named', 'Internet domain name server', author, 8),
	('man_nsec3hash', 'nsec3hash', 'generate NSEC3 hash', author, 8),
	('man_nslookup', 'nslookup', 'query Internet name servers interactively', author, 1),
	('man_nsupdate', 'nsupdate', 'dynamic DNS update utility', author, 1),
	('man_pkcs11-destroy', 'pkcs11-destroy', 'destroy PKCS#11 objects', author, 8),
	('man_pkcs11-keygen', 'pkcs11-keygen', 'generate keys on a PKCS#11 device', author, 8),
	('man_pkcs11-list', 'pkcs11-list', 'list PKCS#11 objects', author, 8),
	('man_pkcs11-tokens', 'pkcs11-tokens', 'list PKCS#11 available tokens', author, 8),
	('man_rndc-confgen', 'rndc-confgen', 'rndc key generation tool', author, 8),
	('man_rndc.conf', 'rndc.conf', 'rndc configuration file', author, 5),
	('man_rndc', 'rndc', 'name server control utility', author, 8),
]
