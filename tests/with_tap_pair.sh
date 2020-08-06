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

cleanup() {
	ip link del br0
	ip link del tap1
	ip link del tap0
}

trap cleanup ERR

ip link add br0 type bridge

ip tuntap add tap0 mode tap
ip link set tap0 addr 2:1:0:0:0:1
ip link set tap0 up
ip link set tap0 master br0
ip addr add dev tap0 192.168.14.1/24

ip tuntap add tap1 mode tap
ip link set tap1 addr 2:1:0:0:0:2
ip link set tap1 up
ip link set tap1 master br0
ip addr add dev tap1 192.168.14.2/24

ip link set dev br0 up
ip link set dev tap0 up
ip link set dev tap1 up

$@

cleanup

