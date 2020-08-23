#!/bin/bash
#
# Copyright (C) 2020 Google LLC
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
#
# test hw checksum offload edge cases of a device under test ("tdev")
# see individual cases below for details

NS_TDEV=tdev
NS_PEER=peer

ADDR_V4_TDEV=192.168.1.1
ADDR_V4_PEER=192.168.1.2

ADDR_V6_TDEV=fdaa::1
ADDR_V6_PEER=fdaa::2

set -eu

do_test() {
	local -r ipver=$1
	local -r dir=$2
	shift
	shift

	if [[ "${dir}" == "to_tdev" ]]; then
		src_ns="${NS_PEER}"
		dst_ns="${NS_TDEV}"
		if [[ "${ipver}" == "-4" ]]; then
			saddr="${ADDR_V4_PEER}"
			daddr="${ADDR_V4_TDEV}"
		else
			saddr="${ADDR_V6_PEER}"
			daddr="${ADDR_V6_TDEV}"
		fi
	else
		src_ns="${NS_TDEV}"
		dst_ns="${NS_PEER}"
		if [[ "${ipver}" == "-4" ]]; then
			saddr="${ADDR_V4_TDEV}"
			daddr="${ADDR_V4_PEER}"
		else
			saddr="${ADDR_V6_TDEV}"
			daddr="${ADDR_V6_PEER}"
		fi
	fi

	# verify udp checksum 0 is sent as 0xFFFF
	# argument '-Z' selects a source port to cause this checksum
	ip netns exec "${dst_ns}" ./csum "${ipver}" -u -S "${saddr}" -D "${daddr}" -R "$@" &
	sleep 0.2
	ip netns exec "${src_ns}" ./csum "${ipver}" -u -S "${saddr}" -D "${daddr}" -T "$@"
	wait
}

do_check_preconditions

# test receive h/w checksumming:
#
# - udp packets with csum that adds up to zero are sent with csum 0xFFFF,
#	 to distinguish these packets from checksum disabled.
#	 arg -Z selects a source port to cause the condition.
#	 arg -U sends from a udp socket to use h/w checksum offload

do_test -4 to_peer -U -Z
do_test -6 to_peer -U -Z

# test receive h/w checksumming:
# - packets with correct csum are delivered
# - packets with bad csum are dropped
# test rx hw csum: accept packets with correct csum

do_test -4 to_tdev
do_test -6 to_tdev

do_test -4 to_tdev -E
do_test -6 to_tdev -E

