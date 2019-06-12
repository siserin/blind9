.. highlight: console

pkcs11-tokens - list PKCS#11 available tokens
=============================================

Synopsis
--------

:program:`pkcs11-tokens` [**-m** module] [**-v**]

Description
-----------

``pkcs11-tokens`` lists the PKCS#11 available tokens with defaults from
the slot/token scan performed at application initialization.

Arguments
---------

**-m** module
   Specify the PKCS#11 provider module. This must be the full path to a
   shared library object implementing the PKCS#11 API for the device.

**-v**
   Make the PKCS#11 libisc initialization verbose.

See Also
--------

:manpage:`pkcs11-destroy(8)`, :manpage:`pkcs11-keygen(8)`, :manpage:`pkcs11-list(8)`
