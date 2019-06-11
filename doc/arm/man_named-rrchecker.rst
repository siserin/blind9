.. highlight: console

named-rrchecker - syntax checker for individual DNS resource records
====================================================================

Synopsis
--------

:program:`named-rrchecker` [**-h**] [**-o** origin] [**-p**] [**-u**] [**-C**] [**-T**] [**-P**]

Description
-----------

``named-rrchecker`` read a individual DNS resource record from standard
input and checks if it is syntactically correct.

The ``-h`` prints out the help menu.

The ``-o origin`` option specifies a origin to be used when interpreting
the record.

The ``-p`` prints out the resulting record in canonical form. If there
is no canonical form defined then the record will be printed in unknown
record format.

The ``-u`` prints out the resulting record in unknown record form.

The ``-C``, ``-T`` and ``-P`` print out the known class, standard type
and private type mnemonics respectively.

See Also
--------

RFC 1034, RFC 1035, :manpage:`named(8)`.
