#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Record a kernel stack trace each time ionic stops a Tx subqueue.

usage()
{
	cat <<EOF
Usage: $0 -i IFNAME [-d SECS] [-o FILE] [-h]
  -i IFNAME   netdev to trace (required)
  -d SECS     stop after this many seconds (default: until Ctrl-C)
  -o FILE     also write the captured trace to FILE
  -h          this help

Enables the ionic:ionic_q_stop tracepoint for IFNAME and attaches a
stacktrace trigger, so every time the driver stops a Tx queue for lack
of ring space you get the event plus the kernel call stack that led to
it.

The stack tells you which stop path fired:
  ionic_maybe_stop_tx <- ionic_start_xmit
      the queue was stopped before posting, because the next skb needs
      more descriptors than are free. A TSO skb whose gso_segs exceeds
      the ring size lands here and can never fit, so the queue stays
      stopped and the watchdog fires. This is the shape seen on the
      IBM tx-timeout.
  ionic_check_stop_tx <- ionic_tx
      the ring filled during normal posting; a completion will wake it.

The stack does not carry the descriptor count. To see how many
descriptors (segments) the stopping skb needed, run alongside:
  echo 'name == "IFNAME" && gso_segs > 1000' \\
      > /sys/kernel/debug/tracing/events/net/net_dev_start_xmit/filter
or a kprobe on ionic_maybe_stop_tx (ndescs arg).

Runs in a private trace instance and removes it on exit, so it does
not disturb other tracing.
EOF
}

DEBUGFS=/sys/kernel/debug
TRACEFS=/sys/kernel/tracing
[[ -d $TRACEFS/events ]] || TRACEFS=$DEBUGFS/tracing

IFNAME=
SECS=
OUT=
while getopts "i:d:o:h" opt; do
	case $opt in
	i) IFNAME=$OPTARG ;;
	d) SECS=$OPTARG ;;
	o) OUT=$OPTARG ;;
	h) usage; exit 0 ;;
	*) usage >&2; exit 1 ;;
	esac
done

die() { echo "$0: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must run as root"
[[ -n $IFNAME ]] || { usage >&2; exit 1; }
[[ -e /sys/class/net/$IFNAME ]] || die "no such netdev: $IFNAME"
[[ $(basename "$(readlink "/sys/class/net/$IFNAME/device/driver")") == ionic ]] ||
	die "$IFNAME is not an ionic netdev"
[[ -d $TRACEFS/events/ionic/ionic_q_stop ]] ||
	die "ionic:ionic_q_stop tracepoint not found (is the ionic driver loaded?)"
[[ -z $SECS || $SECS =~ ^[0-9]+$ ]] || die "-d takes seconds"

INST=$TRACEFS/instances/ionic_qstop_$$
EV=

cleanup()
{
	[[ -n $EV ]] || return
	echo 0 > "$EV/enable" 2>/dev/null
	echo '!stacktrace' > "$EV/trigger" 2>/dev/null
	: > "$EV/filter" 2>/dev/null
	rmdir "$INST" 2>/dev/null
}

mkdir "$INST" || die "cannot create trace instance (need tracefs)"
trap cleanup EXIT
trap 'exit 130' INT TERM
EV=$INST/events/ionic/ionic_q_stop

echo "devname == \"$IFNAME\"" > "$EV/filter" || die "cannot set filter"
echo stacktrace > "$EV/trigger" || die "cannot set stacktrace trigger"
echo 1 > "$EV/enable" || die "cannot enable tracepoint"

echo "tracing ionic_q_stop on $IFNAME${SECS:+ for ${SECS}s}; Ctrl-C to stop"

reader=(cat "$INST/trace_pipe")
if [[ -n $SECS ]]; then
	reader=(timeout "$SECS" cat "$INST/trace_pipe")
fi

if [[ -n $OUT ]]; then
	"${reader[@]}" | tee "$OUT"
else
	"${reader[@]}"
fi
