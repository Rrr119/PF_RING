#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "pfring_flow_balance.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define FB_KEY_FLAG_FRAGMENT 0x01

typedef enum {
  FB_FLOW_EMPTY = 0,
  FB_FLOW_USED = 1,
  FB_FLOW_TOMBSTONE = 2
} fb_flow_state;

typedef struct {
  pfring_fb_key key;
  uint64_t digest;
  uint32_t queue_id;
  uint64_t packets;
  uint8_t state;
  uint8_t explicit_affinity;
} fb_flow;

struct pfring_flow_balancer {
  pthread_mutex_t lock;
  uint32_t num_queues;
  uint32_t max_cpus;

  fb_flow *flows;
  uint32_t flow_slots;
  uint32_t flow_count;

  pfring_fb_queue_stats queues[PFRING_FB_MAX_QUEUES];
  pfring_fb_cpu_stats *cpus;

  uint64_t received_packets;
  uint64_t received_bytes;
  uint64_t packets;
  uint64_t bytes;
  uint64_t drops;
  uint64_t affinity_hits;
  uint64_t affinity_misses;
  uint64_t explicit_flows;
};

static uint64_t fb_splitmix64(uint64_t x) {
  x += 0x9e3779b97f4a7c15ULL;
  x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
  x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
  return x ^ (x >> 31);
}

static uint16_t fb_load_be16(const uint8_t *p) {
  uint16_t v;
  memcpy(&v, p, sizeof(v));
  return ntohs(v);
}

static int fb_have_bytes(size_t offset, size_t need, size_t len) {
  return offset <= len && need <= len - offset;
}

static void fb_key_set_ipv4(pfring_fb_key *key, const uint8_t *src,
                            const uint8_t *dst) {
  key->ip_version = 4;
  memcpy(key->src_addr, src, 4);
  memcpy(key->dst_addr, dst, 4);
}

uint64_t pfring_fb_key_digest(const pfring_fb_key *key) {
  uint64_t hash = 1469598103934665603ULL;
  size_t i, addr_len;

  if(key == NULL)
    return 0;

#define FB_HASH_BYTE(b) do { \
    uint8_t fb_byte = (uint8_t)(b); \
    hash ^= fb_byte; \
    hash *= 1099511628211ULL; \
  } while(0)

  FB_HASH_BYTE(key->vlan & 0xff);
  FB_HASH_BYTE(key->vlan >> 8);
  FB_HASH_BYTE(key->ethertype & 0xff);
  FB_HASH_BYTE(key->ethertype >> 8);
  FB_HASH_BYTE(key->ip_version);
  FB_HASH_BYTE(key->protocol);
  FB_HASH_BYTE(key->flags);
  FB_HASH_BYTE(key->src_port & 0xff);
  FB_HASH_BYTE(key->src_port >> 8);
  FB_HASH_BYTE(key->dst_port & 0xff);
  FB_HASH_BYTE(key->dst_port >> 8);

  addr_len = key->ip_version == 6 ? 16 : 4;
  for(i = 0; i < addr_len; i++)
    FB_HASH_BYTE(key->src_addr[i]);
  for(i = 0; i < addr_len; i++)
    FB_HASH_BYTE(key->dst_addr[i]);

  for(i = 0; i < 6; i++)
    FB_HASH_BYTE(key->src_mac[i]);
  for(i = 0; i < 6; i++)
    FB_HASH_BYTE(key->dst_mac[i]);

#undef FB_HASH_BYTE

  return fb_splitmix64(hash);
}

uint32_t pfring_fb_key_hash(const pfring_fb_key *key) {
  return (uint32_t)(pfring_fb_key_digest(key) & 0xffffffffULL);
}

static int fb_compare_bytes(const uint8_t *a, const uint8_t *b, size_t len) {
  size_t i;

  for(i = 0; i < len; i++) {
    if(a[i] < b[i])
      return -1;
    if(a[i] > b[i])
      return 1;
  }

  return 0;
}

void pfring_fb_key_canonicalize(pfring_fb_key *key) {
  int swap = 0;
  size_t addr_len;

  if(key == NULL)
    return;

  addr_len = key->ip_version == 6 ? 16 : 4;

  if(key->ip_version == 4 || key->ip_version == 6) {
    int cmp = fb_compare_bytes(key->src_addr, key->dst_addr, addr_len);

    if(cmp > 0)
      swap = 1;
    else if(cmp == 0 && key->src_port > key->dst_port)
      swap = 1;
  } else {
    if(fb_compare_bytes(key->src_mac, key->dst_mac, 6) > 0)
      swap = 1;
  }

  if(swap) {
    uint16_t port;
    uint8_t addr[16];
    uint8_t mac[6];

    port = key->src_port;
    key->src_port = key->dst_port;
    key->dst_port = port;

    memcpy(addr, key->src_addr, sizeof(addr));
    memcpy(key->src_addr, key->dst_addr, sizeof(addr));
    memcpy(key->dst_addr, addr, sizeof(addr));

    memcpy(mac, key->src_mac, sizeof(mac));
    memcpy(key->src_mac, key->dst_mac, sizeof(mac));
    memcpy(key->dst_mac, mac, sizeof(mac));
  }

  key->hash = pfring_fb_key_hash(key);
}

int pfring_fb_key_equal(const pfring_fb_key *a, const pfring_fb_key *b) {
  size_t addr_len;

  if(a == NULL || b == NULL)
    return 0;

  addr_len = a->ip_version == 6 || b->ip_version == 6 ? 16 : 4;

  return a->vlan == b->vlan
    && a->ethertype == b->ethertype
    && a->ip_version == b->ip_version
    && a->protocol == b->protocol
    && a->flags == b->flags
    && a->src_port == b->src_port
    && a->dst_port == b->dst_port
    && fb_compare_bytes(a->src_addr, b->src_addr, addr_len) == 0
    && fb_compare_bytes(a->dst_addr, b->dst_addr, addr_len) == 0
    && memcmp(a->src_mac, b->src_mac, 6) == 0
    && memcmp(a->dst_mac, b->dst_mac, 6) == 0;
}

static int fb_parse_l4_ports(pfring_fb_key *key, const uint8_t *pkt,
                             size_t len, size_t l4_offset, int fragmented) {
  if(fragmented) {
    /* Fragments share L3 endpoints; forcing zero keeps them on one queue. */
    key->flags |= FB_KEY_FLAG_FRAGMENT;
    key->src_port = key->dst_port = 0;
    return PFRING_FB_OK;
  }

  if((key->protocol == IPPROTO_TCP || key->protocol == IPPROTO_UDP
      || key->protocol == 132 /* SCTP */)
     && fb_have_bytes(l4_offset, 4, len)) {
    key->src_port = fb_load_be16(pkt + l4_offset);
    key->dst_port = fb_load_be16(pkt + l4_offset + 2);
  } else if((key->protocol == IPPROTO_ICMP || key->protocol == IPPROTO_ICMPV6)
            && fb_have_bytes(l4_offset, 6, len)) {
    uint16_t icmp_id = fb_load_be16(pkt + l4_offset + 4);
    key->src_port = key->dst_port = icmp_id;
  }

  return PFRING_FB_OK;
}

static int fb_parse_ipv4(pfring_fb_key *key, const uint8_t *pkt, size_t len,
                         size_t offset) {
  uint8_t ihl;
  uint16_t frag;
  size_t l4_offset;
  int fragmented;

  if(!fb_have_bytes(offset, sizeof(struct ip), len))
    return PFRING_FB_EINVAL;

  ihl = (pkt[offset] & 0x0f) * 4;
  if(ihl < 20 || !fb_have_bytes(offset, ihl, len))
    return PFRING_FB_EINVAL;

  key->protocol = pkt[offset + 9];
  fb_key_set_ipv4(key, pkt + offset + 12, pkt + offset + 16);
  frag = fb_load_be16(pkt + offset + 6);
  fragmented = ((frag & 0x2000) != 0) || ((frag & 0x1fff) != 0);
  l4_offset = offset + ihl;

  return fb_parse_l4_ports(key, pkt, len, l4_offset, fragmented);
}

static int fb_parse_ipv6(pfring_fb_key *key, const uint8_t *pkt, size_t len,
                         size_t offset) {
  uint8_t next_header;
  size_t l4_offset = offset + 40;
  int fragmented = 0;
  unsigned int hops;

  if(!fb_have_bytes(offset, sizeof(struct ip6_hdr), len))
    return PFRING_FB_EINVAL;

  key->ip_version = 6;
  next_header = pkt[offset + 6];
  memcpy(key->src_addr, pkt + offset + 8, 16);
  memcpy(key->dst_addr, pkt + offset + 24, 16);

  for(hops = 0; hops < 16; hops++) {
    size_t header_len;

    if(next_header == IPPROTO_TCP || next_header == IPPROTO_UDP
       || next_header == IPPROTO_SCTP || next_header == IPPROTO_ICMPV6)
      break;

    if(next_header == 44 /* Fragment header */) {
      if(!fb_have_bytes(l4_offset, 8, len))
        return PFRING_FB_EINVAL;
      next_header = pkt[l4_offset];
      fragmented = 1;
      l4_offset += 8;
      continue;
    }

    if(next_header == IPPROTO_AH) {
      if(!fb_have_bytes(l4_offset, 2, len))
        return PFRING_FB_EINVAL;
      next_header = pkt[l4_offset];
      header_len = (size_t)(pkt[l4_offset + 1] + 2) * 4;
    } else if(next_header == 0 || next_header == 43 || next_header == 60) {
      if(!fb_have_bytes(l4_offset, 2, len))
        return PFRING_FB_EINVAL;
      next_header = pkt[l4_offset];
      header_len = (size_t)pkt[l4_offset + 1] * 8 + 8;
    } else {
      break;
    }

    if(!fb_have_bytes(l4_offset, header_len, len))
      return PFRING_FB_EINVAL;
    l4_offset += header_len;
  }

  key->protocol = next_header;
  return fb_parse_l4_ports(key, pkt, len, l4_offset, fragmented);
}

static int fb_ethertype_is_routable(uint16_t ethertype) {
  return ethertype == ETHERTYPE_IP || ethertype == ETHERTYPE_IPV6
    || ethertype == ETHERTYPE_VLAN || ethertype == 0x88a8 /* QinQ */;
}

/* Walks 802.1Q/QinQ tags starting at payload offset and parses L3. */
static int fb_parse_ethertype(pfring_fb_key *key, const uint8_t *pkt,
                              size_t len, size_t offset,
                              uint16_t ethertype) {
  while(ethertype == ETHERTYPE_VLAN || ethertype == 0x88a8 /* QinQ */) {
    if(!fb_have_bytes(offset, 4, len))
      return PFRING_FB_EINVAL;
    key->vlan = fb_load_be16(pkt + offset) & 0x0fff;
    ethertype = fb_load_be16(pkt + offset + 2);
    offset += 4;
  }

  key->ethertype = ethertype;

  if(ethertype == ETHERTYPE_IP)
    return fb_parse_ipv4(key, pkt, len, offset);
  if(ethertype == ETHERTYPE_IPV6)
    return fb_parse_ipv6(key, pkt, len, offset);

  return PFRING_FB_OK;
}

static int fb_parse_ethernet(pfring_fb_key *key, const uint8_t *pkt,
                             size_t len) {
  uint16_t ethertype;

  if(!fb_have_bytes(0, 14, len))
    return PFRING_FB_EINVAL;

  memcpy(key->dst_mac, pkt, 6);
  memcpy(key->src_mac, pkt + 6, 6);
  ethertype = fb_load_be16(pkt + 12);

  return fb_parse_ethertype(key, pkt, len, 14, ethertype);
}

/*
 * Linux cooked capture. v1 (DLT_LINUX_SLL) is 16 bytes with the protocol at
 * offset 14 and the address at offset 6; v2 (DLT_LINUX_SLL2) is 20 bytes with
 * the protocol at offset 0 and the address at offset 12. Only the source
 * hardware address is recorded, so dst_mac remains zeroed.
 */
static int fb_parse_sll(pfring_fb_key *key, const uint8_t *pkt, size_t len,
                        int version2) {
  uint16_t ethertype;
  uint8_t addr_len;
  size_t addr_offset;
  size_t l3_offset;

  if(version2) {
    if(!fb_have_bytes(0, 20, len))
      return PFRING_FB_EINVAL;
    ethertype = fb_load_be16(pkt + 0);
    addr_len = pkt[11];
    addr_offset = 12;
    l3_offset = 20;
  } else {
    if(!fb_have_bytes(0, 16, len))
      return PFRING_FB_EINVAL;
    ethertype = fb_load_be16(pkt + 14);
    addr_len = pkt[5];
    addr_offset = 6;
    l3_offset = 16;
  }

  if(addr_len > 6)
    addr_len = 6;
  if(addr_len > 0 && fb_have_bytes(addr_offset, addr_len, len))
    memcpy(key->src_mac, pkt + addr_offset, addr_len);

  return fb_parse_ethertype(key, pkt, len, l3_offset, ethertype);
}

int pfring_fb_key_parse_linktype(const uint8_t *packet, size_t packet_len,
                                 int linktype, pfring_fb_key *key) {
  int rc = PFRING_FB_OK;

  if(packet == NULL || key == NULL || packet_len == 0)
    return PFRING_FB_EINVAL;

  memset(key, 0, sizeof(*key));

  switch(linktype) {
  case PFRING_FB_LINK_ETHERNET:
    rc = fb_parse_ethernet(key, packet, packet_len);
    break;

  case PFRING_FB_LINK_LINUX_SLL:
    rc = fb_parse_sll(key, packet, packet_len, 0);
    break;

  case PFRING_FB_LINK_LINUX_SLL2:
    rc = fb_parse_sll(key, packet, packet_len, 1);
    break;

  case PFRING_FB_LINK_RAW:
  case 12 /* DLT_RAW on some platforms */:
    if((packet[0] >> 4) == 6)
      rc = fb_parse_ipv6(key, packet, packet_len, 0);
    else
      rc = fb_parse_ipv4(key, packet, packet_len, 0);
    if(rc == PFRING_FB_OK)
      key->ethertype = (packet[0] >> 4) == 6 ? ETHERTYPE_IPV6
                                             : ETHERTYPE_IP;
    break;

  case PFRING_FB_LINK_AUTO:
  default: {
    uint16_t eth_ethertype = 0;

    /* Raw IP is the common link-less input; keep version-nibble detection. */
    if((packet[0] >> 4) == 4 || (packet[0] >> 4) == 6) {
      int raw_rc;

      key->ethertype = (packet[0] >> 4) == 6 ? ETHERTYPE_IPV6
                                             : ETHERTYPE_IP;
      if((packet[0] >> 4) == 4)
        raw_rc = fb_parse_ipv4(key, packet, packet_len, 0);
      else
        raw_rc = fb_parse_ipv6(key, packet, packet_len, 0);

      if(raw_rc == PFRING_FB_OK) {
        pfring_fb_key_canonicalize(key);
        return PFRING_FB_OK;
      }
      /* Not really IP (e.g. an Ethernet dst MAC): retry with L2 framing. */
      memset(key, 0, sizeof(*key));
    }

    if(fb_have_bytes(0, 14, packet_len))
      eth_ethertype = fb_load_be16(packet + 12);

    /*
     * Divert to cooked capture only when the Ethernet EtherType slot is not a
     * normal L3 type and the SLL signature is unambiguous. Well-formed
     * Ethernet/raw inputs therefore keep their original parse path.
     */
    if(!fb_ethertype_is_routable(eth_ethertype)) {
      /* SLL2: protocol at 0, reserved MBZ at 2, halen byte at 11. */
      if(fb_have_bytes(0, 20, packet_len)
         && fb_ethertype_is_routable(fb_load_be16(packet + 0))
         && fb_load_be16(packet + 2) == 0
         && packet[11] <= 8) {
        rc = fb_parse_sll(key, packet, packet_len, 1);
        if(rc == PFRING_FB_OK) {
          pfring_fb_key_canonicalize(key);
          return PFRING_FB_OK;
        }
        memset(key, 0, sizeof(*key));
      }

      /* SLL v1: address-length high byte zero, low byte <= 8, proto at 14. */
      if(fb_have_bytes(0, 16, packet_len)
         && packet[4] == 0 && packet[5] <= 8
         && fb_ethertype_is_routable(fb_load_be16(packet + 14))) {
        rc = fb_parse_sll(key, packet, packet_len, 0);
        if(rc == PFRING_FB_OK) {
          pfring_fb_key_canonicalize(key);
          return PFRING_FB_OK;
        }
        memset(key, 0, sizeof(*key));
      }
    }

    rc = fb_parse_ethernet(key, packet, packet_len);
    break;
  }
  }

  if(rc == PFRING_FB_OK)
    pfring_fb_key_canonicalize(key);

  return rc;
}

int pfring_fb_key_parse(const uint8_t *packet, size_t packet_len,
                        pfring_fb_key *key) {
  return pfring_fb_key_parse_linktype(packet, packet_len,
                                      PFRING_FB_LINK_AUTO, key);
}

static uint32_t fb_normalize_cpu(const pfring_flow_balancer *fb,
                                 uint32_t cpu_id) {
  if(cpu_id == PFRING_FB_CPU_UNKNOWN) {
    int cpu = sched_getcpu();
    cpu_id = cpu >= 0 ? (uint32_t)cpu : 0;
  }

  if(cpu_id >= fb->max_cpus)
    cpu_id = fb->max_cpus - 1;

  return cpu_id;
}

static int fb_flow_index(const pfring_flow_balancer *fb,
                         const pfring_fb_key *key, uint64_t digest) {
  uint32_t mask = fb->flow_slots - 1;
  uint32_t pos = (uint32_t)digest & mask;
  uint32_t probe;

  for(probe = 0; probe < fb->flow_slots; probe++) {
    uint32_t idx = (pos + probe) & mask;
    const fb_flow *flow = &fb->flows[idx];

    if(flow->state == FB_FLOW_EMPTY)
      return -((int)idx + 3);

    if(flow->state == FB_FLOW_USED && flow->digest == digest
       && pfring_fb_key_equal(&flow->key, key))
      return (int)idx;
  }

  return PFRING_FB_ENOMEM;
}

static int fb_resize_flows(pfring_flow_balancer *fb) {
  uint32_t old_slots = fb->flow_slots;
  fb_flow *old_flows = fb->flows;
  uint32_t new_slots = old_slots * 2;
  fb_flow *new_flows;
  uint32_t i;

  if(new_slots < old_slots || new_slots > (UINT32_MAX / 2 + 1))
    return PFRING_FB_ENOMEM;

  new_flows = calloc(new_slots, sizeof(*new_flows));
  if(new_flows == NULL)
    return PFRING_FB_ENOMEM;

  fb->flows = new_flows;
  fb->flow_slots = new_slots;
  fb->flow_count = 0;

  for(i = 0; i < old_slots; i++) {
    if(old_flows[i].state != FB_FLOW_USED)
      continue;

    int lookup_rc = fb_flow_index(fb, &old_flows[i].key,
                                  old_flows[i].digest);
    if(lookup_rc <= -3) {
      uint32_t slot = (uint32_t)(-lookup_rc - 3);
      fb->flows[slot] = old_flows[i];
      fb->flows[slot].state = FB_FLOW_USED;
      fb->flow_count++;
    }
  }

  free(old_flows);
  return PFRING_FB_OK;
}

static uint32_t fb_choose_queue(const pfring_flow_balancer *fb,
                                uint64_t digest) {
  uint64_t best = UINT64_MAX;
  uint32_t min_count = 0;
  uint32_t i, chosen_index = 0;

  for(i = 0; i < fb->num_queues; i++) {
    if(fb->queues[i].packets < best)
      best = fb->queues[i].packets;
  }

  for(i = 0; i < fb->num_queues; i++) {
    if(fb->queues[i].packets == best)
      min_count++;
  }

  if(min_count <= 1) {
    for(i = 0; i < fb->num_queues; i++) {
      if(fb->queues[i].packets == best)
        return i;
    }
  }

  chosen_index = (uint32_t)(digest % min_count);
  for(i = 0; i < fb->num_queues; i++) {
    if(fb->queues[i].packets == best) {
      if(chosen_index == 0)
        return i;
      chosen_index--;
    }
  }

  return digest % fb->num_queues;
}

static int fb_insert_flow(pfring_flow_balancer *fb,
                          const pfring_fb_key *key, uint64_t digest,
                          uint32_t queue_id, int explicit_affinity) {
  int idx = fb_flow_index(fb, key, digest);
  fb_flow *flow;

  if(idx >= 0) {
    flow = &fb->flows[idx];
    if(explicit_affinity) {
      if(!flow->explicit_affinity)
        fb->explicit_flows++;
      if(flow->queue_id != queue_id) {
        fb->queues[flow->queue_id].flow_count--;
        flow->queue_id = queue_id;
        fb->queues[queue_id].flow_count++;
      }
      flow->explicit_affinity = 1;
    }
    return idx;
  }

  if(fb->flow_count + 1 > (fb->flow_slots * 7) / 10) {
    if(fb_resize_flows(fb) != PFRING_FB_OK)
      return PFRING_FB_ENOMEM;
    idx = fb_flow_index(fb, key, digest);
  }

  if(idx < 0) {
    uint32_t slot;

    if(idx == PFRING_FB_ENOMEM)
      return PFRING_FB_ENOMEM;

    slot = (uint32_t)(-idx - 3);

    if(slot >= fb->flow_slots)
      return PFRING_FB_ENOMEM;

    idx = (int)slot;
  }

  flow = &fb->flows[idx];
  memset(flow, 0, sizeof(*flow));
  flow->key = *key;
  flow->digest = digest;
  flow->queue_id = queue_id;
  flow->state = FB_FLOW_USED;
  flow->explicit_affinity = explicit_affinity ? 1 : 0;
  if(explicit_affinity)
    fb->explicit_flows++;
  fb->queues[queue_id].flow_count++;
  fb->flow_count++;

  return idx;
}

pfring_flow_balancer *pfring_fb_create(uint32_t num_queues,
                                       uint32_t max_cpus) {
  pfring_flow_balancer *fb;
  uint32_t i;

  if(num_queues == 0 || num_queues > PFRING_FB_MAX_QUEUES) {
    errno = EINVAL;
    return NULL;
  }

  if(max_cpus == 0) {
    long configured_cpus = sysconf(_SC_NPROCESSORS_CONF);

    max_cpus = configured_cpus > 0 ? (uint32_t)configured_cpus
                                   : PFRING_FB_MAX_CPUS;
  }
  if(max_cpus > PFRING_FB_MAX_CPUS)
    max_cpus = PFRING_FB_MAX_CPUS;

  fb = calloc(1, sizeof(*fb));
  if(fb == NULL)
    return NULL;

  if(pthread_mutex_init(&fb->lock, NULL) != 0) {
    free(fb);
    return NULL;
  }

  fb->num_queues = num_queues;
  fb->max_cpus = max_cpus;
  fb->flow_slots = PFRING_FB_DEFAULT_FLOW_SLOTS;
  fb->flows = calloc(fb->flow_slots, sizeof(*fb->flows));
  fb->cpus = calloc(max_cpus, sizeof(*fb->cpus));

  if(fb->flows == NULL || fb->cpus == NULL) {
    free(fb->flows);
    free(fb->cpus);
    pthread_mutex_destroy(&fb->lock);
    free(fb);
    return NULL;
  }

  for(i = 0; i < num_queues; i++) {
    fb->queues[i].queue_id = i;
    fb->queues[i].capacity = 0;
  }

  for(i = 0; i < max_cpus; i++) {
    fb->cpus[i].cpu_id = i;
    fb->cpus[i].last_queue = PFRING_FB_CPU_UNKNOWN;
  }

  return fb;
}

void pfring_fb_destroy(pfring_flow_balancer *fb) {
  if(fb == NULL)
    return;

  pthread_mutex_destroy(&fb->lock);
  free(fb->flows);
  free(fb->cpus);
  free(fb);
}

int pfring_fb_set_affinity(pfring_flow_balancer *fb,
                           const pfring_fb_key *key, uint32_t queue_id) {
  pfring_fb_key local;
  uint64_t digest;
  int rc;

  if(fb == NULL || key == NULL || queue_id >= fb->num_queues)
    return PFRING_FB_EINVAL;

  local = *key;
  pfring_fb_key_canonicalize(&local);
  digest = pfring_fb_key_digest(&local);

  pthread_mutex_lock(&fb->lock);
  rc = fb_insert_flow(fb, &local, digest, queue_id, 1);
  pthread_mutex_unlock(&fb->lock);

  return rc >= 0 ? PFRING_FB_OK : rc;
}

int pfring_fb_clear_affinity(pfring_flow_balancer *fb,
                             const pfring_fb_key *key) {
  pfring_fb_key local;
  uint64_t digest;
  int idx;
  int rc = PFRING_FB_ENOENT;

  if(fb == NULL || key == NULL)
    return PFRING_FB_EINVAL;

  local = *key;
  pfring_fb_key_canonicalize(&local);
  digest = pfring_fb_key_digest(&local);

  pthread_mutex_lock(&fb->lock);
  idx = fb_flow_index(fb, &local, digest);
  if(idx >= 0) {
    if(fb->flows[idx].explicit_affinity)
      fb->explicit_flows--;
    fb->queues[fb->flows[idx].queue_id].flow_count--;
    fb->flows[idx].state = FB_FLOW_TOMBSTONE;
    fb->flow_count--;
    rc = PFRING_FB_OK;
  }
  pthread_mutex_unlock(&fb->lock);

  return rc;
}

int pfring_fb_select_queue(pfring_flow_balancer *fb,
                           const pfring_fb_key *key,
                           uint32_t cpu_id,
                           uint32_t *queue_id) {
  pfring_fb_key local;
  uint64_t digest;
  int idx;

  if(fb == NULL || key == NULL || queue_id == NULL)
    return PFRING_FB_EINVAL;

  local = *key;
  pfring_fb_key_canonicalize(&local);
  digest = pfring_fb_key_digest(&local);
  cpu_id = fb_normalize_cpu(fb, cpu_id);

  pthread_mutex_lock(&fb->lock);
  idx = fb_flow_index(fb, &local, digest);
  if(idx >= 0) {
    fb->affinity_hits++;
  } else {
    uint32_t selected = fb_choose_queue(fb, digest);
    idx = fb_insert_flow(fb, &local, digest, selected, 0);
    if(idx < 0) {
      pthread_mutex_unlock(&fb->lock);
      return idx;
    }
    fb->affinity_misses++;
  }

  *queue_id = fb->flows[idx].queue_id;
  fb->cpus[cpu_id].last_queue = *queue_id;
  pthread_mutex_unlock(&fb->lock);

  return PFRING_FB_OK;
}

int pfring_fb_dispatch(pfring_flow_balancer *fb,
                       const pfring_fb_key *key,
                       uint32_t cpu_id, uint64_t packet_len,
                       uint32_t *queue_id) {
  pfring_fb_key local;
  uint64_t digest;
  uint32_t q;
  int idx;
  int rc = PFRING_FB_OK;

  if(fb == NULL || key == NULL)
    return PFRING_FB_EINVAL;

  local = *key;
  pfring_fb_key_canonicalize(&local);
  digest = pfring_fb_key_digest(&local);
  cpu_id = fb_normalize_cpu(fb, cpu_id);

  pthread_mutex_lock(&fb->lock);

  idx = fb_flow_index(fb, &local, digest);
  if(idx >= 0) {
    fb->affinity_hits++;
  } else {
    q = fb_choose_queue(fb, digest);
    idx = fb_insert_flow(fb, &local, digest, q, 0);
    if(idx < 0) {
      pthread_mutex_unlock(&fb->lock);
      return idx;
    }
    fb->affinity_misses++;
  }

  q = fb->flows[idx].queue_id;
  if(queue_id != NULL)
    *queue_id = q;

  fb->received_packets++;
  fb->received_bytes += packet_len;
  fb->queues[q].received_packets++;
  fb->queues[q].received_bytes += packet_len;
  fb->cpus[cpu_id].received_packets++;
  fb->cpus[cpu_id].last_queue = q;

  if(fb->queues[q].capacity != 0
     && fb->queues[q].current_queued >= fb->queues[q].capacity) {
    fb->drops++;
    fb->queues[q].drops++;
    fb->cpus[cpu_id].drops++;
    rc = PFRING_FB_EFULL;
  } else {
    fb->packets++;
    fb->bytes += packet_len;
    fb->queues[q].packets++;
    fb->queues[q].bytes += packet_len;
    fb->queues[q].current_queued++;
    if(fb->queues[q].current_queued > fb->queues[q].peak_queued)
      fb->queues[q].peak_queued = fb->queues[q].current_queued;

    fb->cpus[cpu_id].packets++;
    fb->cpus[cpu_id].bytes += packet_len;
    fb->flows[idx].packets++;
  }

  pthread_mutex_unlock(&fb->lock);
  return rc;
}

int pfring_fb_dispatch_packet(pfring_flow_balancer *fb,
                              const uint8_t *packet, size_t packet_len,
                              uint32_t cpu_id, uint32_t *queue_id) {
  pfring_fb_key key;
  int rc;

  rc = pfring_fb_key_parse(packet, packet_len, &key);
  if(rc != PFRING_FB_OK)
    return rc;

  return pfring_fb_dispatch(fb, &key, cpu_id, packet_len, queue_id);
}

int pfring_fb_set_queue_capacity(pfring_flow_balancer *fb,
                                 uint32_t queue_id, uint64_t capacity) {
  if(fb == NULL || queue_id >= fb->num_queues)
    return PFRING_FB_EINVAL;

  pthread_mutex_lock(&fb->lock);
  fb->queues[queue_id].capacity = capacity;
  pthread_mutex_unlock(&fb->lock);
  return PFRING_FB_OK;
}

int pfring_fb_complete(pfring_flow_balancer *fb,
                       uint32_t queue_id, uint64_t packets) {
  if(fb == NULL || queue_id >= fb->num_queues)
    return PFRING_FB_EINVAL;

  pthread_mutex_lock(&fb->lock);
  if(packets >= fb->queues[queue_id].current_queued)
    fb->queues[queue_id].current_queued = 0;
  else
    fb->queues[queue_id].current_queued -= packets;
  pthread_mutex_unlock(&fb->lock);
  return PFRING_FB_OK;
}

int pfring_fb_report_drop(pfring_flow_balancer *fb,
                          uint32_t queue_id, uint64_t packets) {
  if(fb == NULL || queue_id >= fb->num_queues)
    return PFRING_FB_EINVAL;

  pthread_mutex_lock(&fb->lock);
  fb->drops += packets;
  fb->queues[queue_id].drops += packets;
  pthread_mutex_unlock(&fb->lock);
  return PFRING_FB_OK;
}

int pfring_fb_get_snapshot(pfring_flow_balancer *fb,
                           pfring_fb_snapshot *snapshot) {
  if(fb == NULL || snapshot == NULL)
    return PFRING_FB_EINVAL;

  memset(snapshot, 0, sizeof(*snapshot));

  pthread_mutex_lock(&fb->lock);
  snapshot->api_version = PFRING_FB_API_VERSION;
  snapshot->num_queues = fb->num_queues;
  snapshot->num_cpus = fb->max_cpus;
  snapshot->received_packets = fb->received_packets;
  snapshot->received_bytes = fb->received_bytes;
  snapshot->packets = fb->packets;
  snapshot->bytes = fb->bytes;
  snapshot->drops = fb->drops;
  snapshot->flow_count = fb->flow_count;
  snapshot->affinity_hits = fb->affinity_hits;
  snapshot->affinity_misses = fb->affinity_misses;
  snapshot->explicit_flows = fb->explicit_flows;

  memcpy(snapshot->queues, fb->queues,
         fb->num_queues * sizeof(fb->queues[0]));
  memcpy(snapshot->cpus, fb->cpus,
         fb->max_cpus * sizeof(fb->cpus[0]));
  pthread_mutex_unlock(&fb->lock);

  return PFRING_FB_OK;
}

int pfring_fb_get_queue_stats(pfring_flow_balancer *fb,
                              uint32_t queue_id,
                              pfring_fb_queue_stats *stats) {
  if(fb == NULL || stats == NULL || queue_id >= fb->num_queues)
    return PFRING_FB_EINVAL;

  pthread_mutex_lock(&fb->lock);
  *stats = fb->queues[queue_id];
  pthread_mutex_unlock(&fb->lock);
  return PFRING_FB_OK;
}

int pfring_fb_get_cpu_stats(pfring_flow_balancer *fb,
                            uint32_t cpu_id,
                            pfring_fb_cpu_stats *stats) {
  if(fb == NULL || stats == NULL)
    return PFRING_FB_EINVAL;

  cpu_id = fb_normalize_cpu(fb, cpu_id);
  pthread_mutex_lock(&fb->lock);
  *stats = fb->cpus[cpu_id];
  pthread_mutex_unlock(&fb->lock);
  return PFRING_FB_OK;
}

char *pfring_fb_snapshot_json(const pfring_fb_snapshot *s) {
  char *buf = NULL;
  size_t size = 0;
  FILE *out;
  uint32_t i;

  if(s == NULL)
    return NULL;

  out = open_memstream(&buf, &size);
  if(out == NULL)
    return NULL;

  fprintf(out,
          "{\n"
          "  \"api_version\": %u,\n"
          "  \"num_queues\": %u,\n"
          "  \"num_cpus\": %u,\n"
          "  \"totals\": {\n"
          "    \"received_packets\": %llu,\n"
          "    \"received_bytes\": %llu,\n"
          "    \"packets\": %llu,\n"
          "    \"bytes\": %llu,\n"
          "    \"drop\": %llu,\n"
          "    \"drops\": %llu,\n"
          "    \"flows\": %llu,\n"
          "    \"affinity_hits\": %llu,\n"
          "    \"affinity_misses\": %llu,\n"
          "    \"explicit_flows\": %llu\n"
          "  },\n",
          s->api_version, s->num_queues, s->num_cpus,
          (unsigned long long)s->received_packets,
          (unsigned long long)s->received_bytes,
          (unsigned long long)s->packets,
          (unsigned long long)s->bytes,
          (unsigned long long)s->drops,
          (unsigned long long)s->drops,
          (unsigned long long)s->flow_count,
          (unsigned long long)s->affinity_hits,
          (unsigned long long)s->affinity_misses,
          (unsigned long long)s->explicit_flows);

  fputs("  \"queues\": [\n", out);
  for(i = 0; i < s->num_queues; i++) {
    const pfring_fb_queue_stats *q = &s->queues[i];

    fprintf(out,
            "    {\"queue\": %u, \"flows\": %u, "
            "\"received_packets\": %llu, \"received_bytes\": %llu, "
            "\"packets\": %llu, \"bytes\": %llu, "
            "\"drop\": %llu, \"drops\": %llu, "
            "\"queued\": %llu, \"peak_queued\": %llu, "
            "\"capacity\": %llu}%s\n",
            q->queue_id, q->flow_count,
            (unsigned long long)q->received_packets,
            (unsigned long long)q->received_bytes,
            (unsigned long long)q->packets,
            (unsigned long long)q->bytes,
            (unsigned long long)q->drops,
            (unsigned long long)q->drops,
            (unsigned long long)q->current_queued,
            (unsigned long long)q->peak_queued,
            (unsigned long long)q->capacity,
            i + 1 == s->num_queues ? "" : ",");
  }
  fputs("  ],\n  \"cpus\": [\n", out);

  for(i = 0; i < s->num_cpus; i++) {
    const pfring_fb_cpu_stats *c = &s->cpus[i];

    fprintf(out,
            "    {\"cpu\": %u, \"last_queue\": %u, "
            "\"received_packets\": %llu, \"packets\": %llu, "
            "\"bytes\": %llu, \"drop\": %llu, \"drops\": %llu}%s\n",
            c->cpu_id,
            c->last_queue == PFRING_FB_CPU_UNKNOWN ? UINT32_MAX : c->last_queue,
            (unsigned long long)c->received_packets,
            (unsigned long long)c->packets,
            (unsigned long long)c->bytes,
            (unsigned long long)c->drops,
            (unsigned long long)c->drops,
            i + 1 == s->num_cpus ? "" : ",");
  }

  fputs("  ]\n}\n", out);
  fclose(out);
  return buf;
}

char *pfring_fb_stats_json(pfring_flow_balancer *fb) {
  pfring_fb_snapshot *snapshot;
  char *json;

  if(fb == NULL)
    return NULL;

  snapshot = calloc(1, sizeof(*snapshot));
  if(snapshot == NULL)
    return NULL;

  if(pfring_fb_get_snapshot(fb, snapshot) != PFRING_FB_OK) {
    free(snapshot);
    return NULL;
  }

  json = pfring_fb_snapshot_json(snapshot);
  free(snapshot);
  return json;
}

int pfring_fb_export_json(pfring_flow_balancer *fb, const char *path) {
  char *json;
  FILE *out;

  if(fb == NULL || path == NULL)
    return PFRING_FB_EINVAL;

  json = pfring_fb_stats_json(fb);
  if(json == NULL)
    return PFRING_FB_ENOMEM;

  if(strcmp(path, "-") == 0) {
    fputs(json, stdout);
    free(json);
    return PFRING_FB_OK;
  }

  out = fopen(path, "w");
  if(out == NULL) {
    free(json);
    return PFRING_FB_EINVAL;
  }

  fputs(json, out);
  if(fclose(out) != 0) {
    free(json);
    return PFRING_FB_EINVAL;
  }

  free(json);
  return PFRING_FB_OK;
}

int pfring_fb_export_prometheus(pfring_flow_balancer *fb, const char *path) {
  pfring_fb_snapshot *s;
  FILE *out;
  uint32_t i;

  if(fb == NULL || path == NULL)
    return PFRING_FB_EINVAL;

  s = calloc(1, sizeof(*s));
  if(s == NULL)
    return PFRING_FB_ENOMEM;
  if(pfring_fb_get_snapshot(fb, s) != PFRING_FB_OK) {
    free(s);
    return PFRING_FB_EINVAL;
  }

  out = strcmp(path, "-") == 0 ? stdout : fopen(path, "w");
  if(out == NULL) {
    free(s);
    return PFRING_FB_EINVAL;
  }

  fputs("# HELP pfring_fb_queue_packets Flow-balanced packets per queue.\n"
        "# TYPE pfring_fb_queue_packets counter\n", out);
  for(i = 0; i < s->num_queues; i++)
    fprintf(out, "pfring_fb_queue_packets{queue=\"%u\"} %llu\n", i,
            (unsigned long long)s->queues[i].packets);

  fputs("# HELP pfring_fb_queue_drops Dropped packets per queue.\n"
        "# TYPE pfring_fb_queue_drops counter\n", out);
  for(i = 0; i < s->num_queues; i++)
    fprintf(out, "pfring_fb_queue_drops{queue=\"%u\"} %llu\n", i,
            (unsigned long long)s->queues[i].drops);

  fputs("# HELP pfring_fb_cpu_packets Flow-balanced packets accounted on CPU.\n"
        "# TYPE pfring_fb_cpu_packets counter\n", out);
  for(i = 0; i < s->num_cpus; i++)
    fprintf(out, "pfring_fb_cpu_packets{cpu=\"%u\"} %llu\n", i,
            (unsigned long long)s->cpus[i].packets);

  if(out != stdout)
    fclose(out);
  free(s);
  return PFRING_FB_OK;
}

static void fb_test_key(uint32_t flow_id, uint32_t seed,
                        pfring_fb_key *key) {
  uint32_t x = fb_splitmix64((uint64_t)flow_id + ((uint64_t)seed << 32));

  memset(key, 0, sizeof(*key));
  key->ip_version = 4;
  key->ethertype = ETHERTYPE_IP;
  key->protocol = (x & 1) ? IPPROTO_TCP : IPPROTO_UDP;
  key->vlan = (x >> 8) & 0xfff;

  key->src_addr[0] = 10;
  key->src_addr[1] = (flow_id >> 16) & 0xff;
  key->src_addr[2] = (flow_id >> 8) & 0xff;
  key->src_addr[3] = (flow_id & 0xfe) + 1;
  key->dst_addr[0] = 192;
  key->dst_addr[1] = 168;
  key->dst_addr[2] = 0;
  key->dst_addr[3] = 1;
  key->src_port = 1024 + (flow_id % 60000);
  key->dst_port = (x & 1) ? 443 : 53;
  pfring_fb_key_canonicalize(key);
}

int pfring_fb_run_acceptance(const pfring_fb_acceptance_config *config,
                             pfring_fb_acceptance_result *result) {
  pfring_fb_acceptance_config cfg;
  pfring_flow_balancer *fb;
  uint32_t *queue_of_flow;
  uint32_t flows, packets_per_flow, queues, threshold_bps;
  uint64_t total = 0;
  uint32_t f, seq, q, i;
  int rc = PFRING_FB_OK;

  if(result == NULL)
    return PFRING_FB_EINVAL;

  memset(result, 0, sizeof(*result));
  if(config != NULL)
    cfg = *config;
  else
    memset(&cfg, 0, sizeof(cfg));

  queues = cfg.num_queues ? cfg.num_queues : 4;
  flows = cfg.num_flows ? cfg.num_flows : 4096;
  packets_per_flow = cfg.packets_per_flow ? cfg.packets_per_flow : 32;
  threshold_bps = cfg.deviation_bps ? cfg.deviation_bps
                                   : PFRING_FB_DEFAULT_DEVIATION_BPS;

  if(queues == 0 || queues > PFRING_FB_MAX_QUEUES
     || flows == 0 || flows > 1000000
     || packets_per_flow == 0 || packets_per_flow > 100000
     || threshold_bps > 10000)
    return PFRING_FB_EINVAL;

  memset(&cfg, 0, sizeof(cfg));
  cfg.num_queues = queues;
  cfg.num_flows = flows;
  cfg.packets_per_flow = packets_per_flow;
  cfg.deviation_bps = threshold_bps;
  cfg.seed = config && config->seed ? config->seed : 0x46423431U;
  cfg.capacity = config ? config->capacity : 4;
  cfg.json_path = config ? config->json_path : NULL;
  cfg.verbose = config ? config->verbose : 0;

  fb = pfring_fb_create(queues, queues);
  queue_of_flow = calloc(flows, sizeof(*queue_of_flow));
  if(fb == NULL || queue_of_flow == NULL) {
    pfring_fb_destroy(fb);
    free(queue_of_flow);
    return PFRING_FB_ENOMEM;
  }

  for(f = 0; f < flows; f++)
    queue_of_flow[f] = PFRING_FB_QUEUE_ANY;

  result->ordering_ok = 1;
  result->affinity_ok = 1;

  /* Interleaved rounds emulate several receive CPUs feeding one balancer. */
  for(seq = 0; seq < packets_per_flow; seq++) {
    for(f = 0; f < flows; f++) {
      pfring_fb_key key;
      uint32_t cpu = (seq + f) % queues;

      fb_test_key(f, cfg.seed, &key);
      rc = pfring_fb_dispatch(fb, &key, cpu, 64 + ((f + seq) & 31), &q);
      if(rc != PFRING_FB_OK)
        goto out;

      if(queue_of_flow[f] == PFRING_FB_QUEUE_ANY)
        queue_of_flow[f] = q;
      else if(queue_of_flow[f] != q)
        result->ordering_ok = 0;
    }
  }

  /* Reverse direction must be canonicalized to the same queue. */
  for(f = 0; f < flows && f < 256; f++) {
    pfring_fb_key forward, reverse;
    uint32_t reverse_queue;

    fb_test_key(f, cfg.seed, &forward);
    reverse = forward;
    for(i = 0; i < 4; i++) {
      uint8_t b = reverse.src_addr[i];
      reverse.src_addr[i] = reverse.dst_addr[i];
      reverse.dst_addr[i] = b;
    }
    {
      uint16_t p = reverse.src_port;
      reverse.src_port = reverse.dst_port;
      reverse.dst_port = p;
    }

    if(pfring_fb_select_queue(fb, &reverse, 0, &reverse_queue) != PFRING_FB_OK
       || reverse_queue != queue_of_flow[f])
      result->affinity_ok = 0;
  }

  rc = pfring_fb_get_snapshot(fb, &result->snapshot);
  if(rc != PFRING_FB_OK)
    goto out;

  result->num_queues = queues;
  result->threshold_bps = threshold_bps;
  result->min_packets = UINT64_MAX;

  for(i = 0; i < queues; i++) {
    uint64_t n = result->snapshot.queues[i].packets;
    total += n;
    if(n < result->min_packets)
      result->min_packets = n;
    if(n > result->max_packets)
      result->max_packets = n;
  }

  result->total_packets = total;
  result->mean_packets_x1000 = (total * 1000ULL) / queues;

  for(i = 0; i < queues; i++) {
    uint64_t n = result->snapshot.queues[i].packets;
    int64_t scaled_diff = (int64_t)n * queues - (int64_t)total;
    uint64_t abs_scaled_diff = scaled_diff >= 0
      ? (uint64_t)scaled_diff : (uint64_t)(-scaled_diff);
    uint32_t deviation_bps = total
      ? (uint32_t)((abs_scaled_diff * 10000ULL) / total) : 10000;

    if(deviation_bps > result->max_deviation_bps)
      result->max_deviation_bps = deviation_bps;
  }

  result->distribution_ok = result->max_deviation_bps <= threshold_bps;

  /* Congestion/drop export check with every queue actually dropping. */
  {
    pfring_flow_balancer *drop_fb = pfring_fb_create(queues, queues);
    int json_rc = PFRING_FB_OK;

    result->drop_export_ok = 0;
    if(drop_fb != NULL) {
      uint32_t drop_flows = queues * (cfg.capacity ? cfg.capacity : 4);
      uint32_t repeat;

      for(i = 0; i < queues; i++)
        pfring_fb_set_queue_capacity(drop_fb, i, cfg.capacity ? cfg.capacity : 4);

      for(f = 0; f < drop_flows; f++) {
        pfring_fb_key key;
        fb_test_key(1000000 + f, cfg.seed, &key);
        pfring_fb_dispatch(drop_fb, &key, f % queues, 64, NULL);
      }

      for(repeat = 0; repeat < 2; repeat++) {
        for(f = 0; f < drop_flows; f++) {
          pfring_fb_key key;
          fb_test_key(1000000 + f, cfg.seed, &key);
          (void)pfring_fb_dispatch(drop_fb, &key, f % queues, 64, NULL);
        }
      }

      if(cfg.json_path != NULL)
        json_rc = pfring_fb_export_json(drop_fb, cfg.json_path);

      if(json_rc == PFRING_FB_OK
         && pfring_fb_get_snapshot(drop_fb, &result->snapshot) == PFRING_FB_OK) {
        result->drop_export_ok = 1;
        for(i = 0; i < queues; i++) {
          if(result->snapshot.queues[i].drops == 0)
            result->drop_export_ok = 0;
        }
      }

      pfring_fb_destroy(drop_fb);
    }

    /* Restore the distribution snapshot for callers and final reporting. */
    pfring_fb_get_snapshot(fb, &result->snapshot);
  }

  result->acceptance_ok = result->distribution_ok
    && result->ordering_ok && result->affinity_ok
    && result->drop_export_ok;

  if(cfg.verbose) {
    fprintf(stdout,
            "queues=%u total=%llu min=%llu max=%llu max_deviation_bps=%u "
            "threshold_bps=%u distribution=%s ordering=%s affinity=%s "
            "drop_export=%s\n",
            queues, (unsigned long long)result->total_packets,
            (unsigned long long)result->min_packets,
            (unsigned long long)result->max_packets,
            result->max_deviation_bps, threshold_bps,
            result->distribution_ok ? "PASS" : "FAIL",
            result->ordering_ok ? "PASS" : "FAIL",
            result->affinity_ok ? "PASS" : "FAIL",
            result->drop_export_ok ? "PASS" : "FAIL");
  }

out:
  free(queue_of_flow);
  pfring_fb_destroy(fb);
  return rc;
}
