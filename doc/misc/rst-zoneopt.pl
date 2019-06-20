#!/usr/bin/perl
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

use warnings;
use strict;
use Time::Piece;

if (@ARGV < 1) {
	print STDERR <<'END';
usage:
    perl rst-zoneopt.pl zoneopt_file [YYYY]
END
	exit 1;
}

my $FILE = shift;

my $t = Time::Piece->new();
my $year;
$year = `git log --max-count=1 --date=format:%Y --format='%cd' -- $FILE` or $year = $t->year;
chomp $year;

open (FH, "<", $FILE) or die "Can't open $FILE";

print "::\n\n";

while (<FH>) {
	if (m{// not.*implemented} || m{// obsolete} ||
	    m{// ancient} || m{// test.*only})
	{
		next;
	}

	s{ // not configured}{};
	s{ // may occur multiple times}{};
	s{[[]}{[}g;
	s{[]]}{]}g;
	s{        }{\t}g;

	print "  " . $_;
}
