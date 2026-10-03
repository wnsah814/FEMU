<!--
SPDX-License-Identifier: GPL-2.0-or-later
-->

# der=uffd guest tools

Two guest programs exercise the hold that keeps an instruction going when
it needs more device pages at once than a cache set has ways.

`straddle-probe` runs, inside a guest on a `femu-cxl-ssd` with `der=uffd`,
one instruction that needs six device pages mapped at once: a `movsq` whose
two code bytes straddle a page boundary, reading 8 bytes that straddle a
second one and writing 8 bytes that straddle a third. Each round uses six
fresh pages of the devdax mapping, which it maps executable. With a cache of
fewer than six ways per set, filling the sixth page evicts one of the first,
and the instruction finishes only because the handler holds the thread's
recent pages (see "userfaultfd mapping" in `hw/femu/docs/cxlssd.md`).

```sh
gcc -O2 -o straddle-probe straddle-probe.c
./straddle-probe [rounds] [first page] [dax device] [seconds]
```

It prints one JSON object: the rounds done before the time limit, whether
the limit killed it, the data mismatches and the round latency. With
`cache-pages=4,cache-ways=4` the rounds complete and `uffd-holds` counts one
hold per round.

`pt-stress` puts the guest's page tables on the device. Online the region as
system RAM that the kernel may use for page tables, on a NUMA node of its own
(QEMU needs a `-numa` node for the guest's RAM, or the window joins node 0),
and bind the program to it:

```sh
sudo daxctl reconfigure-device --mode=system-ram --no-movable --force dax0.0
gcc -O2 -pthread -o pt-stress pt-stress.c
numactl --membind=1 ./pt-stress [MiB] [threads] [seconds]
```

Each thread fills its slice of anonymous 4 KiB pages, then reads, checks and
rewrites random ones; every access may need the data page and up to three
page-table pages. It prints the accesses made and the mismatches found;
`Node 1 PageTables` in `/sys/devices/system/node/node1/meminfo` shows the
page tables on the device while it runs.
