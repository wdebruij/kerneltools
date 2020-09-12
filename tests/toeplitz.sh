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
# extended toeplitz test: test rxhash plus, optionally, either (1) rss mapping
# from rxhash to rx queue ('-irqprefix <irq_prefix>') or (2) rps mapping from
# rxhash to cpu ('-rps <rps_map>')
#
# invoke as:
# ./toeplitz.sh -dev <dev> [-u|-t] [-4|-6] \
#   [(-irqprefix <irq_prefix>)|(-rps <rps_map>)]
#
# then generate traffic from another host to this host
# e.g., for i in `seq 10`; do echo "ping $i" | nc -w 0 -6 -u ${HOST} 8000; sleep 0.02; done
#
# see/modify these config options for protocol details:

IPVER=-6
PROTO=-u
DPORT=8000
DEV=""
IRQ_PREFIX=""
RPS_MAP=""

set -e

# Return a list of the receive irq handler cpus
get_rx_irq_cpus() {
	CPUS=""

	for i in /sys/kernel/irq/*
	do
		# lookup relevant IRQs by action name
		[[ -e "$i/actions" ]] || continue
		cat "$i/actions" | grep -q "${IRQ_PREFIX}" || continue
		irqname=$(<"$i/actions")

		# does the IRQ get called
		irqcount=$(cat "$i/per_cpu_count" | tr -d '0,')
		[[ -n "${irqcount}" ]] || continue

		# lookup CPU
		irq=$(basename "$i")
		cpu=$(cat "/proc/irq/$irq/smp_affinity_list")

		# echo "irq ${irq}:${irqname} cpu ${cpu} num-calls ${irqcount}"

		if [[ -z "${CPUS}" ]]; then
			CPUS="${cpu}"
		else
			CPUS="${CPUS},${cpu}"
		fi
	done

	echo "${CPUS}"
}

check_rps_configs() {
	local -r qdir=/sys/class/net/"${DEV}"/queues
	local -r rps_map_zero="$(<${qdir}/rx-0/rps_cpus)"
	for rps_cpus_file in "${qdir}"/rx-*/rps_cpus
	do
		rps_map_curr="$(<${rps_cpus_file})"
		if [[ "${rps_map_curr}" != "${rps_map_zero}" ]]; then
			echo "RPS bitmaps for all rxqs must match for RPS test"
			echo "${qdir}/rx-0/rps_cpus contains: ${rps_map_zero}"
			echo "${rps_cpus_file} contains: ${rps_map_curr}"
			exit 1
		fi
	done
}

check_rps_disabled() {
	local -r RPS_FILE="/sys/class/net/${DEV}/queues/rx-0/rps_cpus"

	local -r RPS_CONF=$(cat "${RPS_FILE}" | tr -d '0,')
	if [[ ! -z ${RPS_CONF} ]]; then
		echo "RPS must be disabled (${RPS_FILE}: ${RPS_CONF} != 0)"
		exit 1
	fi
}

check_rfs_disabled() {
	local -r RFS_FILE="/proc/sys/net/core/rps_sock_flow_entries"

	if [[ -f "${RFS_FILE}" ]]; then
		local -r RFS_CONF=$(< "${RFS_FILE}")
		if [[ "${RFS_CONF}" != "0" ]]; then
			echo "RFS must be disabled (${RFS_FILE}: ${RFS_CONF} != 0)"
			exit 1
		fi
	fi
}

die() {
	echo "$1"
	exit 1
}

show_usage_and_die() {
	echo "Usage: $0 -dev <dev> [-u|-t] [-4|-6] \\"
	echo "  [(-irqprefix <irq_prefix>)|(-rps <rps_map>)]"
	echo "ex: $0 -dev eth0 -u -6 -irqprefix eth0-rx-"
	die "ex: $0 -dev eth0 -t -4 -rps f"
}

check_nic_rxhash_enabled() {
	local -r pattern="receive-hashing:\ on"

	ethtool -k "${DEV}" | grep -q "${pattern}" || die "rxhash must be enabled"
}

parse_opts() {
	while [[ "$1" =~ "-" ]]; do
		if [[ "$1" = "-dev" ]]; then
			shift
			DEV="$1"
		elif [[ "$1" = "-irqprefix" ]]; then
			shift
			IRQ_PREFIX="$1"
		elif [[ "$1" = "-u" || "$1" = "-t" ]]; then
			PROTO="$1"
		elif [[ "$1" = "-4" || "$1" = "-6" ]]; then
			IPVER="$1"
		elif [[ "$1" = "-rps" ]]; then
			shift
			RPS_MAP="$1"
		else
			show_usage_and_die
		fi
		shift
	done

	if [[ -z "${DEV}" ]]; then
		echo "Must specify -dev"
		show_usage_and_die
	fi
}

parse_opts $@
RSS_KEY=$(</proc/sys/net/core/netdev_rss_key)

check_nic_rxhash_enabled

if [[ ! -z "${IRQ_PREFIX}" ]]; then
	# Test RSS: rxhash % num_rxq maps to expected rxqueue.
	# RPS/RFS must be disabled because they move packets between cpus,
	# which breaks the PACKET_FANOUT_CPU identification of RSS decisions.
	check_rps_disabled
	check_rfs_disabled
	./toeplitz "${IPVER}" "${PROTO}" -d "${DPORT}" -i "${DEV}" \
	  -k "${RSS_KEY}" -T 1000 -C "$(get_rx_irq_cpus)" -s -v
elif [[ ! -z "${RPS_MAP}" ]]; then
	# Test RPS: rxhash % num_cpu maps to expected cpu in rps_map.
	# Requires that all rxqueues have the same rps_map.
	check_rps_configs
	check_rfs_disabled
	./toeplitz "${IPVER}" "${PROTO}" -d "${DPORT}" -i "${DEV}" \
	  -k "${RSS_KEY}" -T 1000 -r "0x${RPS_MAP}" -s -v
else
	# Test rxhash: read rxhash only.
	./toeplitz "${IPVER}" "${PROTO}" -d "${DPORT}" -i "${DEV}" \
	  -k "${RSS_KEY}" -T 1000 -s -v
fi
