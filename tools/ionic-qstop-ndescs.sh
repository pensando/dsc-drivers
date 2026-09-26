#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Print the descriptor count each time ionic stops a Tx queue for lack of
# ring space, via a kprobe on ionic_maybe_stop_tx.

usage()
{
	cat <<EOF
Usage: $0 [-t N] [-r REG] [-d SECS] [-o FILE] [-h]
  -t N        only show stops needing more than N descriptors (default 1000)
  -r REG      register holding the ndescs argument:
                %dx  dsc 24.07 driver, ionic_maybe_stop_tx(netdev, q, ndescs)
                     (3-arg, third arg -> %dx)  [default]
                %si  in-tree driver, ionic_maybe_stop_tx(q, ndescs)
                     (2-arg, second arg -> %si)
  -d SECS     stop after this many seconds (default: until Ctrl-C)
  -o FILE     also write the captured trace to FILE
  -h          this help

ionic_maybe_stop_tx() decides, before posting, whether the next skb fits
in the Tx ring. Its ndescs argument is the descriptor count the skb
needs, which for a TSO skb equals gso_segs. A value above the ring size
(num_descs - 1, e.g. 1023 for a 1024-entry ring) is a packet that can
never fit: the queue is stopped and stays stopped, and the watchdog
fires. That is the IBM tx-timeout shape.

The kprobe fires for every Tx queue on every ionic netdev, so the -t
threshold is what keeps the normal small requests out. ndescs alone does
not carry the netdev or queue; correlate with ionic-qstop-stack.sh or
with net:net_dev_start_xmit (its queue_mapping and gso_segs fields).

If every hit shows an implausible value (huge or negative), the register
is wrong for this build: switch -r (%dx vs %si). Verify the driver's
signature, or if the ionic.ko carries BTF/DWARF use perf instead:
  perf probe -m ionic 'ionic_maybe_stop_tx ndescs'

Runs in a private trace instance and removes both the instance and the
kprobe on exit.
EOF
}

DEBUGFS=/sys/kernel/debug
TRACEFS=/sys/kernel/tracing
[[ -d $TRACEFS/events ]] || TRACEFS=$DEBUGFS/tracing

THRESH=1000
REG=%dx
SECS=
OUT=
while getopts "t:r:d:o:h" opt; do
	case $opt in
	t) THRESH=$OPTARG ;;
	r) REG=$OPTARG ;;
	d) SECS=$OPTARG ;;
	o) OUT=$OPTARG ;;
	h) usage; exit 0 ;;
	*) usage >&2; exit 1 ;;
	esac
done

die() { echo "$0: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must run as root"
[[ $THRESH =~ ^[0-9]+$ ]] || die "-t takes a number"
[[ $REG == %?? || $REG == %??? ]] || die "-r takes a register like %dx or %si"
[[ -z $SECS || $SECS =~ ^[0-9]+$ ]] || die "-d takes seconds"
[[ -w $TRACEFS/kprobe_events ]] || die "$TRACEFS/kprobe_events not writable (tracefs? root?)"
grep -q " ionic_maybe_stop_tx" /proc/kallsyms ||
	die "ionic_maybe_stop_tx not found (ionic loaded? symbol inlined?)"

PROBE=mstop_$$
INST=$TRACEFS/instances/ionic_ndescs_$$
EV=
DEFINED=

cleanup()
{
	[[ -n $EV ]] && echo 0 > "$EV/enable" 2>/dev/null
	[[ -d $INST ]] && rmdir "$INST" 2>/dev/null
	[[ -n $DEFINED ]] && echo "-:$PROBE" >> "$TRACEFS/kprobe_events" 2>/dev/null
}

trap cleanup EXIT
trap 'exit 130' INT TERM

echo "p:$PROBE ionic_maybe_stop_tx ndescs=$REG:s32" >> "$TRACEFS/kprobe_events" ||
	die "cannot define kprobe (bad register '$REG'?)"
DEFINED=1

mkdir "$INST" || die "cannot create trace instance"
EV=$INST/events/kprobes/$PROBE
[[ -d $EV ]] || die "kprobe event did not appear"

echo "ndescs > $THRESH" > "$EV/filter" || die "cannot set filter"
echo 1 > "$EV/enable" || die "cannot enable kprobe"

echo "tracing ionic_maybe_stop_tx ndescs>$THRESH (reg $REG)${SECS:+ for ${SECS}s}; Ctrl-C to stop"

reader=(cat "$INST/trace_pipe")
[[ -n $SECS ]] && reader=(timeout "$SECS" cat "$INST/trace_pipe")

if [[ -n $OUT ]]; then
	"${reader[@]}" | tee "$OUT"
else
	"${reader[@]}"
fi
