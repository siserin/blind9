.. highlight: console

dnstap-read - print dnstap data in human-readable form
======================================================

Synopsis
--------

:program:`dnstap-read` [**-m**] [**-p**] [**-x**] [**-y**] {file}

Description
-----------

``dnstap-read`` reads ``dnstap`` data from a specified file and prints
it in a human-readable format. By default, ``dnstap`` data is printed in
a short summary format, but if the ``-y`` option is specified, then a
longer and more detailed YAML format is used instead.

Options
-------

**-m**
   Trace memory allocations; used for debugging memory leaks.

**-p**
   After printing the ``dnstap`` data, print the text form of the DNS
   message that was encapsulated in the ``dnstap`` frame.

**-x**
   After printing the ``dnstap`` data, print a hex dump of the wire form
   of the DNS message that was encapsulated in the ``dnstap`` frame.

**-y**
   Print ``dnstap`` data in a detailed YAML format.

See Also
--------

:manpage:`named(8)`, :manpage:`rndc(8)`, BIND 9 Administrator Reference Manual.
