#!/bin/sh
#
# Copyright (C) 2015  Internet Systems Consortium, Inc. ("ISC")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

# $Id: tests.sh,v 1.1.4.11 2012/02/01 16:54:32 each Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

DIGOPTS="+tcp +noadd +nosea +nostat +noquest +nocomm +nocmd"
DIGCMD="$DIG $DIGOPTS -p 5300"
RNDCCMD="$RNDC -p 9953 -c ../common/rndc.conf"

status=0
t=0

ret=0
t=`expr $t + 1`
echo "I:checking that zones with slash are properly shown in XML output (${t})"
if [ -x ${CURL} -a -x ${XMLLINT} ] ; then
    if ./newstats
    then
        ${CURL} http://10.53.0.1:8053/xml/v3 > curl.out.${t} 2>/dev/null || ret=1
        ${XMLLINT} --xpath '//statistics/views/view/zones/zone[@name="32/1.0.0.127-in-addr.example"]' curl.out.${t} > /dev/null 2>&1 || ret=1
    else
        ${CURL} http://10.53.0.1:8053/xml > curl.out.${t} 2>/dev/null || ret=1
        ${XMLLINT} --xpath '//statistics/views/view/zones/zone/name="32/1.0.0.127-in-addr.example"' curl.out.${t} > /dev/null 2>&1 || ret=1
    fi
else
  echo "I:skipping test as curl and/or xmllint were not found"
fi
if [ $ret != 0 ]; then echo "I:failed"; fi
status=`expr $status + $ret`

echo "I:exit status: $status"
exit $status
