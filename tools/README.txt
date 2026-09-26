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
