/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#ifndef __RESOLVI_COMMON_H__
#define __RESOLVI_COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_eventdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_mbuf_pool_ops.h>
#include <rte_spinlock.h>

#define NB_SOCKETS 8

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* Tx drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256

/*  Configurable number of Rx/Tx ring descriptors */
#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16

#define MAX_TIMER_PERIOD 86400 /* 1 day max */
/* A tsc-based timer responsible for triggering statistics printout */
#define DEFAULT_TIMER_PERIOD \
  10 * rte_get_timer_hz(); /* default period is 10 seconds */

#define VECTOR_SIZE_DEFAULT MAX_PKT_BURST
#define VECTOR_TMO_NS_DEFAULT 1E6 /* 1ms */

#define DNS_MAX_LABEL_LEN 64 /* RFC says 63 */
/* RFC1035 limites to 255 bytes for name length, but we'll use 128.
 * This needs to be divisible by 8 for easy crc
 */
#define DNS_MAX_QUERY_NAME 128

// struct lcore_conf {
//   uint16_t n_rx_queue;
//   uint16_t n_tx_port;
//   uint16_t tx_port_id[RTE_MAX_ETHPORTS];
//   uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
//   void *dns_lookup_struct;
// } __rte_cache_aligned;

// extern struct lcore_conf lcore_conf[RTE_MAX_LCORE];

enum pkt_action {
  CONTINUE = 0,
  PKT_PASS,
  PKT_TX,
};

struct resolvi_dns_hdr {
  rte_be16_t id;
  rte_be16_t flags;
  rte_be16_t qdcount;
  rte_be16_t ancount;
  rte_be16_t nscount;
  rte_be16_t arcount;
} __rte_packed;

/* Per-port statistics struct */
struct resolvi_port_statistics {
  uint64_t tx;
  uint64_t rx;
  uint64_t dropped;
} __rte_cache_aligned;

/* Event vector attributes */
struct resolvi_event_vector_params {
  uint8_t enabled;
  uint16_t size;
  uint64_t timeout_ns;
};

/* Per-port infomation struct */
struct resolvi_port_info {
  uint16_t pair_port;
  bool is_virt;
} __rte_cache_aligned;

/* Helper struct for processing */
struct resolvi_pkt_info {
  uint16_t cur_off;
  uint16_t l3_off;
  uint16_t l4_off;
  uint16_t l7_off;
  union {
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_ipv6_hdr *ipv6_hdr;
  };
  struct rte_udp_hdr *udp_hdr;
  struct resolvi_dns_hdr *dns_hdr;
};

struct resolvi_resources {
  volatile uint8_t force_quit;
  uint8_t mac_updating;
  uint8_t promiscuous_on;
  uint8_t event_mode;
  uint8_t sched_type;
  uint8_t rx_queue_per_lcore;
  uint16_t nb_rxd;
  uint16_t nb_txd;
  uint16_t nb_phys_ports;
  uint16_t nb_virt_ports;
  uint32_t enabled_port_mask;
  uint64_t timer_period;
  struct rte_mempool *pktmbuf_pool;
  struct rte_mempool *evt_vec_pool;
  struct rte_mempool *dns_cache_pool;
  struct rte_mempool *dns_label_pool;
  struct resolvi_port_info
      port_info[RTE_MAX_ETHPORTS]; /* phys<->virt port mapping */
  struct rte_ether_addr eth_addr[RTE_MAX_ETHPORTS];
  struct resolvi_port_statistics port_stats[RTE_MAX_ETHPORTS];
  struct resolvi_event_vector_params evt_vec;
  void *evt_rsrc;
} __rte_cache_aligned;

static __rte_always_inline void resolvi_mac_updating(
    struct rte_mbuf *m, unsigned dst_portid, struct rte_ether_addr *addr) {
  struct rte_ether_hdr *eth;
  struct rte_ether_addr tmp;

  eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

  /* swap src and dst mac addresses */
  rte_ether_addr_copy(&eth->src_addr, &tmp);
  rte_ether_addr_copy(&eth->dst_addr, &eth->src_addr);
  rte_ether_addr_copy(&tmp, &eth->dst_addr);
}

static __rte_always_inline struct resolvi_resources *resolvi_get_rsrc(void) {
  static const char name[RTE_MEMZONE_NAMESIZE] = "rsrc";
  const struct rte_memzone *mz;

  mz = rte_memzone_lookup(name);
  if (mz != NULL) return mz->addr;

  mz = rte_memzone_reserve(name, sizeof(struct resolvi_resources), 0, 0);
  if (mz != NULL) {
    struct resolvi_resources *rsrc = mz->addr;

    memset(rsrc, 0, sizeof(struct resolvi_resources));
    rsrc->mac_updating = true;
    rsrc->event_mode = true;
    rsrc->rx_queue_per_lcore = 1;
    rsrc->sched_type = RTE_SCHED_TYPE_ATOMIC;
    rsrc->timer_period = DEFAULT_TIMER_PERIOD;

    return mz->addr;
  }

  rte_panic("Unable to allocate memory for resolvi resources\n");

  return NULL;
}

int resolvi_create_virtio_user_ports(struct resolvi_resources *rsrc);
int resolvi_event_init_virt_ports(struct resolvi_resources *rsrc);
int resolvi_event_init_ports(struct resolvi_resources *rsrc);
void resolvi_event_worker_cleanup(uint8_t event_d_id, uint8_t port_id,
                                  struct rte_event events[], uint16_t nb_enq,
                                  uint16_t nb_deq, uint8_t is_vector);

#endif /* __RESOLVI_COMMOH_H__ */