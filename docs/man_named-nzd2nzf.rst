.. highlight: console

named-nzd2nzf - convert an NZD database to NZF text format
==========================================================

Synopsis
--------

:program:`named-nzd2nzf` {filename}

Description
-----------

``named-nzd2nzf`` converts an NZD database to NZF format and prints it
to standard output. This can be used to review the configuration of
zones that were added to ``named`` via ``rndc addzone``. It can also be
used to restore the old file format when rolling back from a newer
version of BIND to an older version.

Arguments
---------

filename
   The name of the ``.nzd`` file whose contents should be printed.

See Also
--------

BIND 9 Administrator Reference Manual.

Author
------

Internet Systems Consortium
