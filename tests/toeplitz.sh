#!/bin/bash
#
# extended toeplitz test: test rxhash plus rss mapping from rxhash to rx queue.

set -eu

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

# RPS/RFS must be disabled because they move packets between cpus,
# which breaks the PACKET_FANOUT_CPU identification of RSS decisions.
check_rpsrfs_disabled() {
	local -r RFS_FILE="/proc/sys/net/core/rps_sock_flow_entries"
	local -r RPS_FILE="/sys/class/net/${DEV}/queues/rx-0/rps_cpus"

	local -r RPS_CONF=$(cat "${RPS_FILE}" | tr -d '0,')
	if [[ ! -z ${RPS_CONF} ]]; then
		echo "RPS must be disabled (${RPS_FILE}: ${RPS_CONF} != 0)"
		exit 1
	fi

	if [[ -f "${RFS_FILE}" ]]; then
		local -r RFS_CONF=$(< "${RFS_FILE}")
		if [[ "${RFS_CONF}" != "0" ]]; then
			echo "RFS must be disabled (${RFS_FILE}: ${RFS_CONF} != 0)"
			exit 1
		fi
	fi

}

die() {
	echo "$0"
	exit 1
}

check_nic_rxhash_enabled() {
	local -r pattern="receive-hashing:\ on"

	ethtool -k eth1 | grep -q "${pattern}" || die "rxhash must be enabled"
}

if [[ "$#" != "2" ]]; then
	echo "Usage: $0 [dev] [irq-prefix]"
	echo "   ex: $0 eth0 eth0-rx-"
	exit 1
fi

DEV=$1
IRQ_PREFIX=$2
RSS_KEY=$(</proc/sys/net/core/netdev_rss_key)

check_rpsrfs_disabled
check_nic_rxhash_enabled

./toeplitz_ex -6 -u -d 8000 -i eth1 -k "${RSS_KEY}" -T 1000 -C "$(get_rx_irq_cpus)" -s -v

