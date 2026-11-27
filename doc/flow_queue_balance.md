# Flow Queue Affinity and Load Statistics

PF_RING already provides symmetric RSS rehashing and per-flow kernel clusters.
The optional `pfring_flow_balance` API adds a deterministic flow-affinity table,
per-receive-CPU counters, per-queue drop counters, and JSON/Prometheus export.
It does not change the existing `pfring_open()`, `pfring_recv()`, or
`pfring_stats()` ABI.

## Acceptance

Run the dependency-free acceptance check:

```sh
make acceptance
```

The default case uses four queues, 4096 deterministic flows, and 32 packets
per flow. It verifies:

- maximum queue deviation is at most `FB_DEVIATION_BPS` basis points
  (default `1000`, i.e. 10%);
- every packet of a flow stays on its first selected queue;
- forward and reverse directions resolve to the same queue;
- all four CPU counters are populated;
- every queue exports a non-zero drop counter under a forced-full test.

Generated files are written to
`/tmp/pfring-flow-balance-acceptance/`:

- `distribution-stats.json`: balanced traffic and CPU statistics;
- `queue-drop-stats.json`: per-queue drop statistics.

Override the sample size or threshold with `FB_FLOWS`,
`FB_PACKETS_PER_FLOW`, and `FB_DEVIATION_BPS`.

## Socket API

```c
pfring_enable_flow_balance(ring, 4);

u_int32_t queue;
int rc = pfring_recv_balanced(ring, &buffer, buffer_len, hdr,
                              1, PFRING_FB_CPU_UNKNOWN, &queue);

pfring_fb_snapshot stats;
pfring_get_flow_balance_snapshot(ring, &stats);
pfring_export_flow_balance_json(ring, "/var/run/pfring-flow-stats.json");
```

Applications that already have a receive loop can instead call
`pfring_flow_balance_observe()` after a successful `pfring_recv()`. Do not call
both `pfring_recv_balanced()` and `pfring_flow_balance_observe()` for the same
packet unless double accounting is intended.

`pfring_fb_key_parse()` auto-detects raw IP, Ethernet/VLAN/QinQ and Linux
cooked v1/v2 (`DLT_LINUX_SLL`/`DLT_LINUX_SLL2`) framing. Callers that already
know the capture linktype can pass it directly to
`pfring_fb_key_parse_linktype(pkt, len, PFRING_FB_LINK_LINUX_SLL2, &key)` to
avoid heuristic detection. Parsing is symmetric: swapping the addresses and
ports of a key and canonicalizing yields the same flow, so both directions of a
flow resolve to one queue.

For one legacy PF_RING socket per hardware queue, aggregate existing
`pfring_stats()` counters without enabling the flow table:

```c
pfring *rings[4] = { /* eth0@0 ... eth0@3 */ };
pfring_export_socket_queue_stats(rings, 4, "/var/run/pfring-queues.json");
```

## Production CPU Distribution

The statistics layer makes imbalance visible and preserves flow order, but NIC
interrupt load still requires RSS/IRQ affinity. For four queues:

```sh
ethtool -L eth0 combined 4
pfring_enable_rss_rehash(ring);       /* or pfcount_multichannel -r */
```

Pin the four RX IRQs and capture threads to four distinct cores, or join four
sockets to one `cluster_per_flow_5_tuple` cluster. See `doc/rss.rst` for the
complete RSS and kernel-cluster configuration guide.
