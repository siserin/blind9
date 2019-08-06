#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

#
# Set up interface aliases for bind9 system tests.
#
# IPv4: 10.53.0.{1..10}				RFC 1918
#       10.53.1.{1..2}
#       10.53.2.{1..2}
# IPv6: fd92:7065:b8e:ffff::{1..10}		ULA
#       fd92:7065:b8e:99ff::{1..2}
#       fd92:7065:b8e:ff::{1..2}
#       fd92:7065:b8e:fffe::10.53.0.4
#

SYSTEMTESTTOP="$(cd -P -- "$(dirname -- "$0")" && pwd -P)"
. "$SYSTEMTESTTOP/conf.sh"

export SYSTEMTESTTOP

sys=$($SHELL "$TOP/config.guess")

use_ip=
case "$sys" in
        *-*-linux*)
                if type ip > /dev/null; then
                        use_ip=yes
                elif type ifconfig > /dev/null; then
                        :
                else
                        echo "$0: can't find ip or ifconfig" >&2
                        exit 1
                fi
                ;;
esac

#
# up <family> <interface-number> <address>
#
up() {
	case "$sys" in
	    *-pc-solaris2.5.1)
		case $1 in
		inet) ifconfig lo0:$2 $3 netmask 0xffffffff up ;;
		esac
		;;
	    *-sun-solaris2.[6-7])
		case $1 in
		inet) ifconfig lo0:$2 $3 netmask 0xffffffff up ;;
		esac
		;;
	    *-*-solaris2.[8-9]|*-*-solaris2.1[0-9])
		case $1 in
		inet)
			/sbin/ifconfig lo0:$2 plumb
			/sbin/ifconfig lo0:$2 $3 up
			;;
		inet6)
			/sbin/ifconfig lo0:$2 inet6 plumb
			/sbin/ifconfig lo0:$2 inet6 $3 up
			;;
		esac
		;;
	    *-*-linux*)
		case $use_ip in
		yes)
			case $1 in
			inet) ip address add $3/24 dev lo:$2 ;;
			inet6) ip address add $3/64 dev lo ;;
			esac
			;;
		*)
			case $1 in
			inet) ifconfig lo:$2 $3 up netmask 255.255.255.0 ;;
			inet6) ifconfig lo inet6 add $3/64 ;;
			esac
			;;
		esac
		;;
	    *-unknown-freebsd*)
		case $1 in
		inet) ifconfig lo0 $3 alias netmask 0xffffffff ;;
		inet6) ifconfig lo0 inet6 $3 alias ;;
		esac
		;;
	    *-unknown-dragonfly*|*-unknown-netbsd*|*-unknown-openbsd*)
		case $1 in
		inet) ifconfig lo0 $3 alias netmask 255.255.255.0 ;;
		inet6) ifconfig lo0 inet6 $3 alias ;;
		esac
		;;
	    *-*-bsdi[3-5].*)
		case $1 in
		inet) ifconfig lo0 add $3 netmask 255.255.255.0 ;;
		esac
		;;
	    *-dec-osf[4-5].*)
		case $1 in
		inet) ifconfig lo0 alias $3 ;;
		esac
		;;
	    *-sgi-irix6.*)
		case $1 in
		inet) ifconfig lo0 alias $3 ;;
		esac
		;;
	    *-*-sysv5uw7*|*-*-sysv*UnixWare*|*-*-sysv*OpenUNIX*)
		case $1 in
		inet) ifconfig lo0 $3 alias netmask 0xffffffff ;;
		esac
		;;
	    *-ibm-aix4.*|*-ibm-aix5.*)
		case $1 in
		inet) ifconfig lo0 alias $3 ;;
		inet6) ifconfig lo0 inet6 alias -dad $3/64 ;;
		esac
		;;
	    hpux)
		case $1 in
		inet) ifconfig lo0:$2 $3 netmask 255.255.255.0 up ;;
		inet6) ifconfig lo0:$2 inet6 $3 up ;;
		esac
		;;
	    *-sco3.2v*)
		case $1 in
		inet) ifconfig lo0 alias $3 ;;
		esac
		;;
	    *-darwin*)
		case $1 in
		inet) ifconfig lo0 alias $3 ;;
		inet6) ifconfig lo0 inet6 $3 alias ;;
		esac
		;;
	    *-cygwin*)
		echo "Please run ifconfig.bat as Administrator."
		exit 1
		;;
	    *)
		echo "Don't know how to set up interface.  Giving up."
		exit 1
	esac
}

#
# down <family> <interface-number> <address>
#
down() {
	case "$sys" in
	    *-pc-solaris2.5.1)
		case $1 in
		inet) ifconfig lo0:$2 0.0.0.0 down ;;
		esac
		;;
	    *-sun-solaris2.[6-7])
		case $1 in
		inet) ifconfig lo0:$2 $3 down ;;
		esac
		;;
	    *-*-solaris2.[8-9]|*-*-solaris2.1[0-9])
		case $1 in
		inet)
			ifconfig lo0:$2 $3 down
			ifconfig lo0:$2 $3 unplumb
			;;
		inet6)
			ifconfig lo0:$2 inet6 down
			ifconfig lo0:$2 inet6 unplumb
			;;
		esac
		;;
	    *-*-linux*)
		case $use_ip in
		yes)
			case $1 in
			inet) ip address del $3/24 dev lo:$2 ;;
			inet6) ip address del $3/64 dev lo ;;
			esac
			;;
		*)
			case $1 in
			inet) ifconfig lo:$2 $3 down ;;
			inet6) ifconfig lo inet6 del $3/64 ;;
			esac
			;;
		esac
		;;
	    *-unknown-freebsd*)
		case $1 in
		inet) ifconfig lo0 $3 delete ;;
		inet6) ifconfig lo0 inet6 $3 delete ;;
		esac
		;;
	    *-unknown-netbsd*)
		case $1 in
		inet) ifconfig lo0 $3 delete ;;
		net6) ifconfig lo0 inet6 $3 delete ;;
		esac
		;;
	    *-unknown-openbsd*)
		case $1 in
		inet) ifconfig lo0 $3 delete ;;
		inet6) fconfig lo0 inet6 $3 delete ;;
		esac
		;;
	    *-*-bsdi[3-5].*)
		case $1 in
		inet) ifconfig lo0 remove $3 ;;
		esac
		;;
	    *-dec-osf[4-5].*)
		case $1 in
		inet) ifconfig lo0 -alias $3 ;;
		esac
		;;
	    *-sgi-irix6.*)
		case $1 in
		inet) ifconfig lo0 -alias $3 ;;
		esac
		;;
	    *-*-sysv5uw7*|*-*-sysv*UnixWare*|*-*-sysv*OpenUNIX*)
		case $1 in
		inet) ifconfig lo0 -alias $3 ;;
		esac
		;;
	    *-ibm-aix4.*|*-ibm-aix5.*)
		case $1 in
		inet) ifconfig lo0 delete $3 ;;
		inet6) ifconfig lo0 delete inet6 $3/64 ;;
		esac
		;;
	    hpux)
		case $1 in
		inet) ifconfig lo0:$int 0.0.0.0 ;;
		inet6) ifconfig lo0:$int inet6 :: ;;
		esac
		;;
	    *-sco3.2v*)
		case $1 in
		inet) ifconfig lo0 -alias $3 ;;
		esac
		;;
	    *darwin*)
		case $1 in
		inet) ifconfig lo0 -alias $3 ;;
		inet6) ifconfig lo0 inet6 $3 delete ;;
		esac
		;;
	    *-cygwin*)
		echo "Please run ifconfig.bat as Administrator."
		exit 1
		;;
	    *)
		echo "Don't know how to destroy interface.  Giving up."
		exit 1
	esac
}

case "$1" in

    start|up)
	for i in 0 1 2 3
	do
		case $i in
		  0) ipv6="ff" ;;
		  1) ipv6="99" ;;
		  2) ipv6="00" ;;
		  *) ipv6="" ;;
		esac
		for ns in 1 2 3 4 5 6 7 8 9 10
		do
			int=`expr $i \* 10 + $ns`
			case $i in
			[012])
				[ $i -gt 0 -a $ns -gt 2 ] && break
				up inet $int 10.53.$i.$ns
				up inet6 $int fd92:7065:b8e:${ipv6}ff::$ns
				;;
			3)
				[ $ns -ne 4 ] && continue
				up inet6 $int fd92:7065:b8e:fffe::10.53.0.$ns
				;;
			esac
		done
	done
	;;

    stop|down)
	for i in 0 1 2 3
	do
		case $i in
		  0) ipv6="ff" ;;
		  1) ipv6="99" ;;
		  2) ipv6="00" ;;
		  *) ipv6="" ;;
		esac
		for ns in 1 2 3 4 5 6 7 8 9 10
		do
			int=`expr $i \* 10 + $ns`
			case $i in
			[012])
				[ $i -gt 0 -a $ns -gt 2 ] && break
				down inet $int 10.53.$i.$ns
				down inet6 $int fd92:7065:b8e:${ipv6}ff::$ns
				;;
			3)
				[ $ns -ne 4 ] && break
				down inet6 $int fd92:7065:b8e:fffe::10.53.0.$ns
				;;
			esac
		done
	done
	;;

	*)
		echo "Usage: $0 { up | down }"
		exit 1
esac
