#ifndef PFRING_FLOW_BALANCE_H
#define PFRING_FLOW_BALANCE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PFRING_FB_API_VERSION 1
#define PFRING_FB_MAX_QUEUES 64
#define PFRING_FB_MAX_CPUS 1024
#define PFRING_FB_CPU_UNKNOWN UINT32_MAX
#define PFRING_FB_QUEUE_ANY UINT32_MAX
#define PFRING_FB_DEFAULT_FLOW_SLOTS 4096

/* Link framing for pfring_fb_key_parse_linktype(). */
#define PFRING_FB_LINK_AUTO 0
#define PFRING_FB_LINK_ETHERNET 1      /* DLT_EN10MB */
#define PFRING_FB_LINK_RAW 101         /* LINKTYPE_RAW / raw IPv4/IPv6 */
#define PFRING_FB_LINK_LINUX_SLL 113   /* DLT_LINUX_SLL (cooked v1) */
#define PFRING_FB_LINK_LINUX_SLL2 276  /* DLT_LINUX_SLL2 (cooked v2) */

/* Acceptance default: no queue may differ from the mean by more than 10%. */
#define PFRING_FB_DEFAULT_DEVIATION_BPS 1000

typedef enum {
  PFRING_FB_OK = 0,
  PFRING_FB_EINVAL = -1,
  PFRING_FB_ENOMEM = -2,
  PFRING_FB_EFULL = -3,
  PFRING_FB_ENOENT = -4,
  PFRING_FB_ETOOMANY = -5
} pfring_fb_error;

typedef struct pfring_flow_balancer pfring_flow_balancer;

/*
 * The key is normally canonicalized.  Reverse directions of the same flow
 * therefore resolve to one queue, which also matches RSS/rehash expectations.
 */
typedef struct {
  uint32_t hash;
  uint16_t vlan;
  uint16_t ethertype;
  uint8_t ip_version;
  uint8_t protocol;
  uint8_t flags;
  uint8_t reserved;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t src_addr[16];
  uint8_t dst_addr[16];
  uint8_t src_mac[6];
  uint8_t dst_mac[6];
} pfring_fb_key;

typedef struct {
  uint32_t queue_id;
  uint32_t flow_count;
  uint64_t received_packets;
  uint64_t received_bytes;
  uint64_t packets;
  uint64_t bytes;
  uint64_t drops;
  uint64_t current_queued;
  uint64_t peak_queued;
  uint64_t capacity;
} pfring_fb_queue_stats;

typedef struct {
  uint32_t cpu_id;
  uint32_t last_queue;
  uint64_t received_packets;
  uint64_t packets;
  uint64_t bytes;
  uint64_t drops;
} pfring_fb_cpu_stats;

typedef struct {
  uint32_t api_version;
  uint32_t num_queues;
  uint32_t num_cpus;
  uint64_t received_packets;
  uint64_t received_bytes;
  uint64_t packets;
  uint64_t bytes;
  uint64_t drops;
  uint64_t flow_count;
  uint64_t affinity_hits;
  uint64_t affinity_misses;
  uint64_t explicit_flows;
  pfring_fb_queue_stats queues[PFRING_FB_MAX_QUEUES];
  pfring_fb_cpu_stats cpus[PFRING_FB_MAX_CPUS];
} pfring_fb_snapshot;

typedef struct {
  uint32_t num_queues;
  uint32_t num_flows;
  uint32_t packets_per_flow;
  uint32_t deviation_bps;
  uint32_t seed;
  uint32_t capacity;
  const char *json_path;
  int verbose;
} pfring_fb_acceptance_config;

typedef struct {
  uint32_t num_queues;
  uint64_t total_packets;
  uint64_t min_packets;
  uint64_t max_packets;
  uint64_t mean_packets_x1000;
  uint32_t max_deviation_bps;
  uint32_t threshold_bps;
  int distribution_ok;
  int ordering_ok;
  int affinity_ok;
  int drop_export_ok;
  int acceptance_ok;
  pfring_fb_snapshot snapshot;
} pfring_fb_acceptance_result;

/* Lifecycle. max_cpus may be 0 to use the system CPU count. */
pfring_flow_balancer *pfring_fb_create(uint32_t num_queues, uint32_t max_cpus);
void pfring_fb_destroy(pfring_flow_balancer *fb);

/*
 * Packet parsing and hashing. Ethernet, raw IP and Linux SLL/SLL2 inputs are
 * accepted. pfring_fb_key_parse() auto-detects the framing; callers that know
 * the capture linktype should use pfring_fb_key_parse_linktype().
 */
int pfring_fb_key_parse(const uint8_t *packet, size_t packet_len,
                        pfring_fb_key *key);
int pfring_fb_key_parse_linktype(const uint8_t *packet, size_t packet_len,
                                 int linktype, pfring_fb_key *key);
void pfring_fb_key_canonicalize(pfring_fb_key *key);
int pfring_fb_key_equal(const pfring_fb_key *a, const pfring_fb_key *b);
uint64_t pfring_fb_key_digest(const pfring_fb_key *key);
uint32_t pfring_fb_key_hash(const pfring_fb_key *key);

/* Explicit affinity pins a flow before packets arrive. */
int pfring_fb_set_affinity(pfring_flow_balancer *fb,
                           const pfring_fb_key *key, uint32_t queue_id);
int pfring_fb_clear_affinity(pfring_flow_balancer *fb,
                             const pfring_fb_key *key);

/*
 * Select a queue without recording a packet. Unknown flows are assigned to the
 * least-loaded queue and pinned for the lifetime of the balancer.
 */
int pfring_fb_select_queue(pfring_flow_balancer *fb,
                           const pfring_fb_key *key,
                           uint32_t cpu_id,
                           uint32_t *queue_id);

/* Parse + dispatch convenience entry point. */
int pfring_fb_dispatch_packet(pfring_flow_balancer *fb,
                              const uint8_t *packet, size_t packet_len,
                              uint32_t cpu_id, uint32_t *queue_id);

/*
 * Account one packet/octet for a canonical flow key. If queue capacity is
 * non-zero and exhausted, PFRING_FB_EFULL is returned and drop counters are
 * incremented. Packets of an existing flow are never moved to another queue.
 */
int pfring_fb_dispatch(pfring_flow_balancer *fb,
                       const pfring_fb_key *key,
                       uint32_t cpu_id, uint64_t packet_len,
                       uint32_t *queue_id);

int pfring_fb_set_queue_capacity(pfring_flow_balancer *fb,
                                 uint32_t queue_id, uint64_t capacity);
int pfring_fb_complete(pfring_flow_balancer *fb,
                       uint32_t queue_id, uint64_t packets);
int pfring_fb_report_drop(pfring_flow_balancer *fb,
                         uint32_t queue_id, uint64_t packets);

int pfring_fb_get_snapshot(pfring_flow_balancer *fb,
                           pfring_fb_snapshot *snapshot);
int pfring_fb_get_queue_stats(pfring_flow_balancer *fb,
                              uint32_t queue_id,
                              pfring_fb_queue_stats *stats);
int pfring_fb_get_cpu_stats(pfring_flow_balancer *fb,
                            uint32_t cpu_id,
                            pfring_fb_cpu_stats *stats);

/* The returned string is malloc()-allocated and must be free()d. */
char *pfring_fb_snapshot_json(const pfring_fb_snapshot *snapshot);
char *pfring_fb_stats_json(pfring_flow_balancer *fb);
int pfring_fb_export_json(pfring_flow_balancer *fb, const char *path);
int pfring_fb_export_prometheus(pfring_flow_balancer *fb, const char *path);

/* Deterministic 4-queue acceptance core used by tests/run_flow_balance_acceptance.sh. */
int pfring_fb_run_acceptance(const pfring_fb_acceptance_config *config,
                             pfring_fb_acceptance_result *result);

/* Compatibility names for callers that prefer the queue-balancer wording. */
#define pfring_queue_balancer pfring_flow_balancer
#define pfring_queue_balancer_create pfring_fb_create
#define pfring_queue_balancer_destroy pfring_fb_destroy
#define pfring_queue_balancer_dispatch pfring_fb_dispatch
#define pfring_queue_balancer_export_json pfring_fb_export_json
#define pfring_queue_balancer_get_snapshot pfring_fb_get_snapshot

#ifdef __cplusplus
}
#endif

#endif /* PFRING_FLOW_BALANCE_H */
