#!/bin/sh

lockfile=get_port_range.lock
statefile=get_port_range.state

get_port_range() {
    if ( set -o noclobber; echo "$$" > "${lockfile}") 2> /dev/null; then
	trap 'rm -f "${lockfile}"; exit $?' INT TERM EXIT

	port_range=$(cat "${statefile}" 2>/dev/null)

	if [ -z "${port_range}" ]; then
	    port_range=32000
	fi

	echo $((port_range+100)) > get_port_range.state

	# clean up after yourself, and release your trap
        rm -f "${lockfile}"
        trap - INT TERM EXIT
	echo "${port_range}"
    else
	echo 0
    fi
}

tries=10

while [ "${tries}" -gt 0 ]; do
    start_port=$(get_port_range)
    if [ "${start_port}" -gt 0 ]; then
	echo "${start_port}"
	exit 0
    fi
    sleep 1
    tries=$((tries-1))
done

exit 1
