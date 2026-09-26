#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Snapshot every Tx queue of an ionic netdev when a Tx timeout fires.

usage()
{
	cat <<EOF
Usage: $0 [-i IFNAME] [-d DIR] [-n] [-h]
  -i IFNAME   only trigger on this netdev (default: any ionic netdev)
  -d DIR      parent directory for the output (default: .)
  -n          collect now for -i IFNAME instead of waiting for a timeout
  -h          this help

Waits for the net:net_dev_xmit_timeout tracepoint, then records the
state of every Tx queue on the netdev that timed out, twice, 1 s apart,
and writes DIR/ionic-txtmo-<ifname>-<date>/ plus a .tgz of it.

Set /sys/module/ionic/parameters/tx_timeout_recover to N first. With Y
the driver rebuilds the queues right after the timeout and the snapshot
races the rebuild.

The kernel reports only the lowest-numbered stuck queue per watchdog
firing, so all queues are collected and the stuck ones are found by
comparing the two snapshots: STUCK means infl > 0 and tail unchanged.

Files:
  meta.txt       trigger event, clocks, kernel, driver, module params
  snap1.txt      one line per Tx queue (fields below), first pass
  snap2.txt      the same, 1 s later
  stuck.txt      queues that made no progress between the two passes
  raw/<qdir>/    q_desc_blob and cq_desc_blob for stuck and reported queues
  debugfs.txt    every scalar debugfs file of the LIF
  sysfs.txt      queues/tx-N/tx_timeout and byte_queue_limits/*
  ethtool.txt    ethtool -i -S -g -l -a -c
  dmesg.txt      last 500 kernel log lines

Snapshot fields:
  q head tail infl   Tx ring producer, consumer, descriptors in flight
  cq_tail dc         next completion slot the driver reads, expected color
  cqc cidx cst       color, comp_index, status of the entry at cq_tail
  pend               Y if that entry is written but unread (cqc == dc)
  stop wake drop pkts  debugfs q counters (pkts needs the debugfs stats fix)
  bql bqlim          byte_queue_limits inflight and limit
  tmo                queues/tx-N/tx_timeout
  imask icred        mask and credits of the queue's interrupt
EOF
}

DEBUGFS=/sys/kernel/debug
TRACEFS=/sys/kernel/tracing
[[ -d $TRACEFS/events ]] || TRACEFS=$DEBUGFS/tracing
PARAM=/sys/module/ionic/parameters/tx_timeout_recover

IFNAME=
OUTDIR=.
NOW=0
while getopts "i:d:nh" opt; do
	case $opt in
	i) IFNAME=$OPTARG ;;
	d) OUTDIR=$OPTARG ;;
	n) NOW=1 ;;
	h) usage; exit 0 ;;
	*) usage >&2; exit 1 ;;
	esac
done

die() { echo "$0: $*" >&2; exit 1; }

rd() { local v; read -r v < "$1" 2>/dev/null || v=-; printf '%s' "$v"; }

qdir()
{
	local d
	for d in "$1"/L*-"$2$3" "$1/${2}_$3"; do
		[[ -d $d ]] && { echo "$d"; return; }
	done
}

regval()
{
	awk -v k="$2" '$1 == k { print $3 }' "$1" 2>/dev/null
}

snapshot()
{
	local ifname=$1 lif=$2 qs n txd rxd idir cqt dsz dc cqc cidx cst pend
	local head tail nd infl comp

	for qs in /sys/class/net/"$ifname"/queues/tx-*; do
		n=${qs##*-}
		txd=$(qdir "$lif" tx "$n")
		[[ -n $txd ]] || continue
		rxd=$(qdir "$lif" rx "$n")

		head=$(rd "$txd/q/head")
		tail=$(rd "$txd/q/tail")
		nd=$(rd "$txd/q/num_descs")
		cqt=$(rd "$txd/cq/tail")
		dsz=$(rd "$txd/cq/desc_size")
		dc=$(rd "$txd/cq/done_color")
		[[ $dc == Y ]] && dc=1
		[[ $dc == N ]] && dc=0

		infl=-
		[[ $head =~ ^[0-9]+$ && $tail =~ ^[0-9]+$ && $nd =~ ^[0-9]+$ ]] &&
			(( nd > 0 )) && infl=$(( (head - tail + nd) % nd ))

		cqc=- cidx=- cst=- pend=-
		if [[ $cqt =~ ^[0-9]+$ && $dsz =~ ^[0-9]+$ ]] && (( dsz >= 16 )); then
			comp=($(dd if="$txd/cq/desc_blob" bs="$dsz" skip="$cqt" \
				count=1 2>/dev/null | od -An -v -tu1))
			if (( ${#comp[@]} >= 16 )); then
				cqc=$(( (comp[15] & 0x80) ? 1 : 0 ))
				cidx=$(( comp[2] | (comp[3] << 8) ))
				cst=${comp[0]}
				pend=N
				[[ $cqc == "$dc" ]] && pend=Y
			fi
		fi

		idir=$txd/intr
		[[ -d $idir ]] || idir=$rxd/intr

		printf 'q=%s head=%s tail=%s infl=%s cq_tail=%s dc=%s cqc=%s cidx=%s cst=%s pend=%s stop=%s wake=%s drop=%s pkts=%s bql=%s bqlim=%s tmo=%s imask=%s icred=%s\n' \
			"$n" "$head" "$tail" "$infl" "$cqt" "$dc" "$cqc" "$cidx" \
			"$cst" "$pend" "$(rd "$txd/q/stop")" "$(rd "$txd/q/wake")" \
			"$(rd "$txd/q/drop")" "$(rd "$txd/q/tx_stats/pkts")" \
			"$(rd "$qs/byte_queue_limits/inflight")" \
			"$(rd "$qs/byte_queue_limits/limit")" \
			"$(rd "$qs/tx_timeout")" \
			"$(regval "$idir/intr_ctrl" mask)" \
			"$(regval "$idir/intr_ctrl" credits)"
	done | sort -t= -k2 -n
}

collect()
{
	local ifname=$1 repq=$2 trigger=$3 bdf lif out n d q

	bdf=$(basename "$(readlink "/sys/class/net/$ifname/device")")
	lif=$(ls -d "$DEBUGFS/ionic/$bdf"/lif* 2>/dev/null | head -n 1)
	[[ -d $lif ]] || die "no ionic debugfs directory for $ifname ($bdf)"

	out=$OUTDIR/ionic-txtmo-$ifname-$(date +%Y%m%d-%H%M%S)
	mkdir -p "$out/raw" || die "cannot create $out"

	snapshot "$ifname" "$lif" > "$out/snap1.txt"
	sleep 1
	snapshot "$ifname" "$lif" > "$out/snap2.txt"

	{
		echo "trigger: $trigger"
		echo "date: $(date '+%F %T %z')"
		echo "uptime: $(cut -d' ' -f1 /proc/uptime) (CLOCK_BOOTTIME; raw dmesg can differ)"
		echo "kernel: $(uname -r)"
		echo "netdev: $ifname  pci: $bdf  debugfs: $lif"
		echo "reported queue: ${repq:--}"
		echo "--- module parameters ---"
		grep -H . /sys/module/ionic/parameters/* 2>/dev/null
	} > "$out/meta.txt"

	awk 'NR == FNR {
		for (i = 1; i <= NF; i++) { split($i, kv, "="); a[kv[1]] = kv[2] }
		t1[a["q"]] = a["tail"]; i1[a["q"]] = a["infl"]; next
	}
	{
		for (i = 1; i <= NF; i++) { split($i, kv, "="); b[kv[1]] = kv[2] }
		q = b["q"]
		if (i1[q] ~ /^[0-9]+$/ && i1[q] > 0 &&
		    b["infl"] ~ /^[0-9]+$/ && b["infl"] > 0 && t1[q] == b["tail"])
			print "STUCK " $0
	}' "$out/snap1.txt" "$out/snap2.txt" > "$out/stuck.txt"

	for q in $(awk '{ sub("q=", "", $2); print $2 }' "$out/stuck.txt") $repq; do
		d=$(qdir "$lif" tx "$q")
		[[ -n $d && ! -d $out/raw/${d##*/} ]] || continue
		mkdir -p "$out/raw/${d##*/}"
		cat "$d/q/desc_blob" > "$out/raw/${d##*/}/q_desc_blob" 2>/dev/null
		cat "$d/cq/desc_blob" > "$out/raw/${d##*/}/cq_desc_blob" 2>/dev/null
	done

	grep -r '' --exclude='*blob*' "$lif" > "$out/debugfs.txt" 2>/dev/null

	for n in /sys/class/net/"$ifname"/queues/tx-*; do
		grep -H . "$n/tx_timeout" "$n"/byte_queue_limits/* 2>/dev/null
	done > "$out/sysfs.txt"

	for n in -i -S -g -l -a -c; do
		echo "=== ethtool $n $ifname ==="
		ethtool "$n" "$ifname" 2>&1
	done > "$out/ethtool.txt"

	dmesg 2>/dev/null | tail -n 500 > "$out/dmesg.txt"

	tar -C "$(dirname "$out")" -czf "$out.tgz" "$(basename "$out")"

	echo "reported queue: ${repq:--}"
	if [[ -s $out/stuck.txt ]]; then
		echo "stuck queues:"
		sed 's/^STUCK /  /' "$out/stuck.txt"
	else
		echo "no queue made zero progress between the two passes"
	fi
	echo "output: $out  ($out.tgz)"
	echo "collect firmware state now, then: echo Y > $PARAM"
}

INST=

cleanup()
{
	[[ -n $INST && -d $INST ]] || return
	echo 0 > "$INST/events/net/net_dev_xmit_timeout/enable" 2>/dev/null
	rmdir "$INST" 2>/dev/null
}

[[ $EUID -eq 0 ]] || die "must run as root"
[[ -d $DEBUGFS/ionic ]] || die "$DEBUGFS/ionic not found (debugfs mounted? ionic loaded?)"
if [[ -n $IFNAME ]]; then
	[[ -e /sys/class/net/$IFNAME ]] || die "no such netdev: $IFNAME"
	[[ $(basename "$(readlink "/sys/class/net/$IFNAME/device/driver")") == ionic ]] ||
		die "$IFNAME is not an ionic netdev"
fi

if (( NOW )); then
	[[ -n $IFNAME ]] || die "-n needs -i IFNAME"
	collect "$IFNAME" "" "manual (-n)"
	exit 0
fi

if [[ ! -e $PARAM ]]; then
	echo "warning: driver has no tx_timeout_recover; the queues are rebuilt right after the timeout" >&2
elif [[ $(rd "$PARAM") != N ]]; then
	echo "warning: tx_timeout_recover is $(rd "$PARAM"); set it to N to hold the stalled queue" >&2
fi

[[ -d $TRACEFS/events/net/net_dev_xmit_timeout ]] ||
	die "net:net_dev_xmit_timeout tracepoint not available"

INST=$TRACEFS/instances/ionic_txtmo_$$
mkdir "$INST" || die "cannot create trace instance $INST"
trap cleanup EXIT
trap 'exit 130' INT TERM

filter='driver == "ionic"'
[[ -n $IFNAME ]] && filter="$filter && name == \"$IFNAME\""
echo "$filter" > "$INST/events/net/net_dev_xmit_timeout/filter" ||
	die "cannot set tracepoint filter"
echo 1 > "$INST/events/net/net_dev_xmit_timeout/enable" ||
	die "cannot enable tracepoint"

echo "waiting for an ionic Tx timeout${IFNAME:+ on $IFNAME}; Ctrl-C to stop"
while read -r line; do
	[[ $line =~ dev=([^[:space:]]+)\ driver=ionic\ queue=([0-9]+) ]] && break
done < "$INST/trace_pipe"
[[ -n ${BASH_REMATCH[1]} ]] || die "trace pipe closed"

collect "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "$line"
