/* SPDX-License-Identifier: LGPL-2.1-or-later */  // Inherited from systemd

#ifndef __RESOLVI_CACHE_H__
#define __RESOLVI_CACHE_H__

#include <rte_hash.h>
#include <rte_hash_crc.h>

#include "resolvi_common.h"

/* RFC 1035 say 512 is the maximum, for classic unicast DNS */
#define DNS_PACKET_UNICAST_SIZE_MAX 512u

/* Never cache more than 4K entries. RFC 1536, Section 5 suggests to
 * leave DNS caches unbounded, but that's crazy. */
#define CACHE_MAX 4096

/* We never keep any item longer than 2h in our cache unless StaleRetentionSec
 * is greater than zero. */
#define CACHE_TTL_MAX_HZ (2 * 60 * 60 * rte_get_timer_hz())

/* The max TTL for stale data is set to 30 seconds. See RFC 8767, Section 6. */
#define CACHE_STALE_TTL_MAX_HZ (30 * rte_get_timer_hz())

/* How long to cache strange rcodes, i.e. rcodes != SUCCESS and != NXDOMAIN
 * (specifically: that's only SERVFAIL for now) */
#define CACHE_TTL_STRANGE_RCODE_HZ (10 * rte_get_timer_hz())

union dns_query_name {
  struct {
    char name[DNS_MAX_QUERY_NAME];
  };
};

typedef enum dns_cache_item_type {
  DNS_CACHE_POSITIVE,
  DNS_CACHE_NODATA,
  DNS_CACHE_NXDOMAIN,
  DNS_CACHE_RCODE, /* "strange" RCODE (effective only SERVFAIL for now) */
} dns_cache_item_type;

struct dns_cache_item {
  dns_cache_item_type type;
  uint64_t until;
  char full_packet[DNS_PACKET_UNICAST_SIZE_MAX];
} __rte_cache_aligned;

static inline uint32_t hash_dns_name_crc(const void *data,
                                         __rte_unused uint32_t data_len,
                                         uint32_t init_val) {
  const char *k;
  const uint32_t *p;
  int i;

  k = (const char *)data;
  p = (const uint32_t *)k;

  for (i = 0; i < DNS_MAX_QUERY_NAME / 4; i++) {
    init_val = rte_hash_crc_4byte(*(p + i), init_val);
  }

  return init_val;
}

void setup_cache(struct resolvi_resources *rsrc, const int socketid);
void setup_hash(struct resolvi_resources *rsrc, const int socketid);
void setup_label(struct resolvi_resources *rsrc, const int socketid);
struct rte_hash *get_resolvi_cache_lookup_struct(const int socketid);
struct dns_cache_item *get_resolvi_cache(const int socket_id,
                                         const int cache_id);
void *del_resolvi_cache(const int socket_id, const int cache_id);

#endif /* __RESOLVI_CACHE_H__ */