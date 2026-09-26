tools
=====

Debugging helpers for the host ionic driver. They are not built or
installed with the driver.


ionic-tx-timeout-snapshot.sh
----------------------------

Captures the state of every Tx queue on an ionic netdev at the moment a
Tx timeout fires, so the stalled queues can be examined together with the
matching firmware state.

Requirements

  - root
  - debugfs mounted, with an ionic driver built with CONFIG_DEBUG_FS
    (/sys/kernel/debug/ionic/<bdf>/lif0/ must exist)
  - tracefs with the net:net_dev_xmit_timeout tracepoint
  - ethtool, dd, od, awk, tar
  - an ionic driver with the tx_timeout_recover module parameter, so the
    stalled queues are held instead of rebuilt. Without it the script
    still runs, but its snapshot races the queue rebuild.

Usage

  echo N > /sys/module/ionic/parameters/tx_timeout_recover
  ./ionic-tx-timeout-snapshot.sh -i <ifname> -d /var/tmp
      ... wait for the timeout; the script prints the stuck queues
      ... and the output path, then exits
      ... collect firmware state
  echo Y > /sys/module/ionic/parameters/tx_timeout_recover

  After "echo Y", the next watchdog firing, about 5 s later, runs the
  normal queue rebuild. An ifdown/ifup is not needed.

  -i IFNAME   only trigger on this netdev (default: any ionic netdev)
  -d DIR      parent directory for the output (default: .)
  -n          collect now for -i IFNAME instead of waiting for a timeout
  -h          help, including the field reference

  While tx_timeout_recover is N, only the stalled queues' traffic is
  blocked. The other queues keep running. The kernel logs "NETDEV
  WATCHDOG" and "Tx Timeout triggered" about every 5 s while the queue
  stays stopped.

How it works

  1. It creates a private trace instance, enables net:net_dev_xmit_timeout
     there with the filter driver == "ionic" (plus name == IFNAME with
     -i), and blocks reading its trace_pipe. It uses no CPU while waiting
     and doesn't touch the global trace buffer.
  2. When the watchdog fires, the event wakes the read. The script takes
     the netdev and queue from the event.
  3. It snapshots every Tx queue of that netdev, waits 1 s, and snapshots
     them again.
  4. It compares the two passes and marks a queue STUCK if it has
     descriptors in flight (infl > 0) and its tail did not move.
  5. It saves the rest of the data (see Output), packs it into a .tgz,
     removes the trace instance and exits.

  Every queue is collected because dev_watchdog() stops scanning at the
  first queue, in index order, that has passed the timeout. Each firing
  reports and counts (queues/tx-N/tx_timeout) only that queue. Other
  stuck queues never appear in the log.

Output

  DIR/ionic-txtmo-<ifname>-<YYYYmmdd-HHMMSS>/ and a .tgz of it:

  meta.txt        trigger event, date, uptime, kernel, netdev, PCI
                  address, reported queue, module parameters
  snap1.txt       one line per Tx queue, first pass
  snap2.txt       the same, 1 s later
  stuck.txt       the snap2 lines of queues marked STUCK
  raw/<qdir>/     q_desc_blob and cq_desc_blob: Tx and completion rings
                  of the stuck and reported queues
  debugfs.txt     every scalar debugfs file of the LIF
  sysfs.txt       queues/tx-N/tx_timeout and byte_queue_limits/*
  ethtool.txt     ethtool -i -S -g -l -a -c
  dmesg.txt       last 500 kernel log lines

Snapshot fields

  q               Tx queue index, same as "txq N" in dmesg, queues/tx-N
                  and debugfs L0-txN
  head            driver producer index: next Tx descriptor slot to fill
  tail            driver consumer index: oldest descriptor not yet
                  completed
  infl            (head - tail) mod ring size: descriptors not yet
                  completed
  cq_tail         next completion slot the driver will read
  dc              done_color: the color the driver expects on this lap of
                  the completion ring
  cqc cidx cst    color, comp_index and status of the completion entry at
                  cq_tail, decoded from cq/desc_blob
  pend            Y if that entry is written but not yet processed
                  (cqc == dc)
  stop wake drop  debugfs q/ counters
  pkts            debugfs q/tx_stats/pkts
  bql bqlim       byte_queue_limits/inflight and limit
  tmo             queues/tx-N/tx_timeout
  imask icred     mask and credits of the queue's interrupt
                  (intr/intr_ctrl)

Reading a stuck queue

  pend=Y, icred about equal to infl
      Completions were posted but not processed: interrupt or NAPI.
  pend=N
      The device never completed the work: doorbell or firmware.
  infl near the ring size (q/num_descs in debugfs.txt), stop counted
      The driver stopped the queue because the ring was full.
  bql > bqlim with the ring well short of full
      BQL stopped the queue. With a full ring, bql > bqlim also holds
      and says nothing, because the limit shrinks when no completions
      come back.
  stopped with infl=0 (not in stuck.txt)
      Lost wakeup in the driver.

Caveats

  - The completion decode assumes the struct ionic_txq_comp layout:
    status at byte 0, comp_index at bytes 2-3 (little endian), color in
    bit 7 of byte 15. If that layout changes, cqc, cidx, cst and pend are
    wrong.
  - pkts and the other tx_stats values are only correct with the debugfs
    stats pointer fix (linux-ionic 69d361bc). Before it, queue N reads
    queue 2N's counters.
  - The 1 s comparison can flag a queue that stalls only briefly. With
    tx_timeout_recover=N, a truly stuck queue stays stuck in both passes.
  - uptime in meta.txt is CLOCK_BOOTTIME. Raw dmesg and trace timestamps
    use a different clock, which drifts from it over long uptimes.
    Correlate with dmesg -T or the trigger line's timestamp.
  - The script takes one snapshot per run, with no history before the
    timeout.


Reproducing a Tx timeout
------------------------

For testing the script and tx_timeout_recover without waiting for a
field failure. The method starves the NAPI thread of one or more Tx
queues on an idle CPU. The device keeps posting completions that nothing
processes, the ring fills, the queue stops, and the watchdog fires after
about 5 s. Stalling two queues also shows the script finding a stuck
queue the kernel never reports.

This disrupts traffic on the chosen queues and runs a SCHED_FIFO busy
loop on one CPU with RT throttling off. Use a test host, an idle CPU,
and keep the loop under about 30 s (below rcu_cpu_stall_timeout,
/sys/module/rcupdate/parameters/rcu_cpu_stall_timeout).

  1. Setup:

     IF=<ifname>
     PG=/proc/net/pktgen
     modprobe pktgen
     echo 1 > /sys/class/net/$IF/threaded
     echo rem_device_all > $PG/kpktgend_10
     echo "add_device $IF" > $PG/kpktgend_10
     for kv in "pkt_size 64" "dst_mac 02:00:00:00:00:01" \
               "dst 198.51.100.1" "count 2000" "ratep 20000"; do
         echo "$kv" > $PG/$IF
     done

  2. Find the NAPI thread of each target queue (5 and 40 here). Send
     2000 packets on the queue; its thread is the one that woke about
     2000 times:

     snap() {
         for p in $(pgrep -f "napi/$IF"); do
             echo "$p $(awk '/^voluntary_ctxt/ {print $2}' \
                 /proc/$p/status)"
         done | sort
     }
     for q in 5 40; do
         echo "queue_map_min $q" > $PG/$IF
         echo "queue_map_max $q" > $PG/$IF
         snap > /tmp/b; echo start > $PG/pgctrl; snap > /tmp/a
         join /tmp/b /tmp/a |
             awk -v q=$q '$3-$2 >= 1900 && $3-$2 <= 2100 {
                 print "q" q ": " $1 }'
     done
     echo rem_device_all > $PG/kpktgend_10

  3. Disable recovery and arm the script:

     echo N > /sys/module/ionic/parameters/tx_timeout_recover
     ./ionic-tx-timeout-snapshot.sh -i $IF -d /var/tmp &

  4. Pin the NAPI threads to an idle CPU at SCHED_IDLE, start the busy
     loop on that CPU, and drive traffic into both queues:

     CPU=<idle cpu>
     for pid in <q5 pid> <q40 pid>; do
         taskset -pc $CPU $pid
         chrt -i -p 0 $pid
     done
     echo -1 > /proc/sys/kernel/sched_rt_runtime_us
     timeout 25 chrt -f 99 taskset -c $CPU \
         bash -c 'while :; do :; done' &
     for q in 5 40; do
         echo "add_device $IF@$q" > $PG/kpktgend_10
         for kv in "pkt_size 64" "dst_mac 02:00:00:00:00:01" \
                   "dst 198.51.100.1" "count 20000" "ratep 5000" \
                   "queue_map_min $q" "queue_map_max $q"; do
             echo "$kv" > "$PG/$IF@$q"
         done
     done
     echo start > $PG/pgctrl &

  5. Expected:

     - dmesg shows "NETDEV WATCHDOG ... transmit queue 5" followed by
       "Tx Timeout recovery disabled, queues left as-is", about every
       5 s. Only queue 5 is ever named.
     - The script prints "reported queue: 5" and lists both q5 and q40
       as stuck, with pend=Y and icred equal to infl. q40 has tmo=0.
     - raw/L0-tx5/ and raw/L0-tx40/ hold the rings (num_descs *
       desc_size bytes each, 16384 for a 1024-entry ring).
     - While the busy loop runs, q/head and q/tail of the stuck queues
       stay the same across watchdog firings: nothing rebuilt them.

  6. Resume and verify recovery:

     echo Y > /sys/module/ionic/parameters/tx_timeout_recover

     The next firing logs "Tx Timeout triggered" without the "recovery
     disabled" line. Once the busy loop ends, NAPI runs, the queues are
     rebuilt, and q/head and q/tail reset to 0.

  7. Clean up:

     echo 950000 > /proc/sys/kernel/sched_rt_runtime_us
     echo stop > $PG/pgctrl
     echo rem_device_all > $PG/kpktgend_10
     rmmod pktgen
     echo 0 > /sys/class/net/$IF/threaded

     950000 is the usual default; restore whatever sched_rt_runtime_us
     held before step 4. The NAPI threads remain until the next module
     reload and are idle once threaded is 0.


ionic-qstop-stack.sh
--------------------

Records a kernel stack trace each time the driver stops a Tx subqueue.
Enables the ionic:ionic_q_stop tracepoint for one netdev with a
stacktrace trigger, in a private trace instance that is removed on exit.

Usage

  ./ionic-qstop-stack.sh -i <ifname> [-d SECS] [-o FILE]

  -i IFNAME   netdev to trace (required)
  -d SECS     stop after this many seconds (default: until Ctrl-C)
  -o FILE     also write the captured trace to FILE

Reading the stack

  The top frames name the stop path:

  ionic_maybe_stop_tx <- ionic_start_xmit
      The queue was stopped before posting, because the next skb needs
      more descriptors than are free. A TSO skb whose gso_segs exceeds
      the ring size lands here and can never fit: the queue stays
      stopped and the watchdog fires. This is the IBM tx-timeout shape.

  ionic_check_stop_tx <- ionic_tx
      The ring filled during normal posting; a completion will wake it.

  ionic_tx_tso never appears: the stop is decided before it is called,
  and ionic_tx_tso has no stop of its own.

  Example (a stop from an oversized TSO skb injected for test):

    ionic_q_stop: <ifname>: queue[0]
     => ionic_maybe_stop_tx
     => ionic_start_xmit
     => dev_hard_start_xmit
     => sch_direct_xmit
     => __dev_queue_xmit
     ...

Getting the descriptor count

  The stack does not carry how many descriptors the stopping skb needed.
  Both stop paths above look identical in the stack, so to tell an
  oversized-TSO stop from an ordinary full ring, capture the count too:

    # segment count of every large GSO skb handed to the netdev
    cd /sys/kernel/debug/tracing
    echo 'name == "<ifname>" && gso_segs > 1000' \
        > events/net/net_dev_start_xmit/filter
    echo 1 > events/net/net_dev_start_xmit/enable
    cat trace_pipe        # prints gso_size, gso_segs, len, queue_mapping

    # or the ndescs argument at the exact stop (dsc 24.07: 3-arg, %dx)
    echo 'p:mstop ionic_maybe_stop_tx ndescs=%dx:s32' > kprobe_events
    echo 'ndescs > 1000' > events/kprobes/mstop/filter
    echo 1 > events/kprobes/mstop/enable

  A gso_segs or ndescs above the Tx ring size (num_descs - 1, e.g. 1023
  for a 1024-entry ring) is a packet that can never fit.
