#!/bin/bash

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

