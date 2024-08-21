/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include <stdbool.h>
#include <getopt.h>

#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_eventdev.h>
#include <rte_event_eth_rx_adapter.h>
#include <rte_event_eth_tx_adapter.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_spinlock.h>

#include "resolvi_event.h"

#define RESOLVI_EVENT_SINGLE 0x1
#define RESOLVI_EVENT_BURST 0x2
#define RESOLVI_EVENT_TX_DIRECT 0x4 /* Is Internal Port Event */
#define RESOLVI_EVENT_TX_ENQ 0x8    /* Is General Event */
#define RESOLVI_EVENT_UPDT_MAC 0x10

static inline int resolvi_event_service_enable(uint32_t service_id) {
  uint8_t min_service_count = UINT8_MAX;
  uint32_t slcore_array[RTE_MAX_LCORE];
  uint32_t slcore = 0;
  uint8_t service_count;
  int32_t slcore_count;

  if (!rte_service_lcore_count()) return -ENOENT;

  slcore_count = rte_service_lcore_list(slcore_array, RTE_MAX_LCORE);
  if (slcore_count < 0) return -ENOENT;
  /* Get the core which has least number of services running. */
  while (slcore_count--) {
    /* Reset default mapping */
    if (rte_service_map_lcore_set(service_id, slcore_array[slcore_count], 0) !=
        0)
      return -ENOENT;
    service_count =
        rte_service_lcore_count_services(slcore_array[slcore_count]);
    if (service_count < min_service_count) {
      slcore = slcore_array[slcore_count];
      min_service_count = service_count;
    }
  }
  if (rte_service_map_lcore_set(service_id, slcore, 1) != 0) return -ENOENT;

  return rte_service_lcore_start(slcore);
}

void resolvi_event_service_setup(struct resolvi_resources *rsrc) {
  struct resolvi_event_resources *evt_rsrc = rsrc->evt_rsrc;
  struct rte_event_dev_info evdev_info;
  uint32_t service_id, caps;
  int ret, i;

  /* Running eventdev scheduler service on service core. 8< */
  rte_event_dev_info_get(evt_rsrc->event_d_id, &evdev_info);
  if (!(evdev_info.event_dev_cap & RTE_EVENT_DEV_CAP_DISTRIBUTED_SCHED)) {
    ret = rte_event_dev_service_id_get(evt_rsrc->event_d_id, &service_id);
    if (ret != -ESRCH && ret != 0)
      rte_panic("Error in getting eventdev service \n");
    ret = resolvi_event_service_enable(service_id);
    if (ret && ret != -EALREADY)
      rte_panic("Error in enabling eventdev service \n");
  }
  /* >8 End of running eventdev scheduler service on service core. */

  /* Gets service ID for Rx/Tx adapters. 8< */
  for (i = 0; i < evt_rsrc->rx_adptr.nb_rx_adptr; i++) {
    ret = rte_event_eth_rx_adapter_caps_get(
        evt_rsrc->event_d_id, evt_rsrc->rx_adptr.rx_adptr[i], &caps);
    if (ret < 0)
      rte_panic("Failed to get Rx adatper[%d] caps\n",
                evt_rsrc->rx_adptr.rx_adptr[i]);
    ret = rte_event_eth_rx_adapter_service_id_get(
        evt_rsrc->rx_adptr.rx_adptr[i], &service_id);
    if (ret != ESRCH && ret != 0)
      rte_panic("Error in getting Rx adapter[%d] service\n",
                evt_rsrc->rx_adptr.rx_adptr[i]);
    ret = resolvi_event_service_enable(service_id);
    if (ret && ret != -EALREADY)
      rte_panic("Error in enabling Rx adapter[%d] service\n",
                evt_rsrc->rx_adptr.rx_adptr[i]);
    printf("Enabled Rx service %d\n", service_id);
  }

  for (i = 0; i < evt_rsrc->tx_adptr.nb_tx_adptr; i++) {
    ret = rte_event_eth_tx_adapter_caps_get(
        evt_rsrc->event_d_id, evt_rsrc->tx_adptr.tx_adptr[i], &caps);
    if (ret < 0)
      rte_panic("Failed to get Tx adapter[%d] caps\n",
                evt_rsrc->tx_adptr.tx_adptr[i]);
    ret = rte_event_eth_tx_adapter_service_id_get(
        evt_rsrc->tx_adptr.tx_adptr[i], &service_id);
    if (ret != -ESRCH && ret != 0)
      rte_panic("Error in getting Tx adapter[%d] service\n",
                evt_rsrc->tx_adptr.tx_adptr[i]);
    ret = resolvi_event_service_enable(service_id);
    if (ret && ret != -EALREADY)
      rte_panic("Error in enabling Tx adapter[%d] service\n",
                evt_rsrc->tx_adptr.tx_adptr[i]);
    printf("Enabled Tx service %d\n", service_id);
  }
  fflush(stdout);
  /* >8 End of get service ID for RX/TX adapters. */
}

static void resolvi_event_capability_setup(
    struct resolvi_event_resources *evt_rsrc) {
  uint32_t caps = 0;
  uint16_t i;
  int ret;

  RTE_ETH_FOREACH_DEV(i) {
    ret = rte_event_eth_tx_adapter_caps_get(0, i, &caps);
    if (ret) rte_panic("Invalid capability for Tx adaptor port %d\n", i);

    evt_rsrc->tx_mode_q |= !(caps & RTE_EVENT_ETH_TX_ADAPTER_CAP_INTERNAL_PORT);
  }

  if (evt_rsrc->tx_mode_q)
    resolvi_event_set_generic_ops(&evt_rsrc->ops);
  else
    resolvi_event_set_internal_port_ops(&evt_rsrc->ops);
}

static __rte_noinline int resolvi_get_free_event_port(
    struct resolvi_event_resources *evt_rsrc) {
  static int index;
  int port_id;

  rte_spinlock_lock(&evt_rsrc->evp.lock);
  if (index >= evt_rsrc->evp.nb_ports) {
    printf("No free event port is available\n");
    return -1;
  }

  port_id = evt_rsrc->evp.event_p_id[index];
  index++;
  rte_spinlock_unlock(&evt_rsrc->evp.lock);

  return port_id;
}

static __rte_always_inline void resolvi_event_phys_handle(
    struct resolvi_resources *rsrc, struct rte_event *ev,
    struct resolvi_event_resources *evt_rsrc, const uint64_t timer_period,
    const uint32_t flags, const int socket_id) {
  struct resolvi_pkt_info info = {
      .cur_off = 0,
  };
  struct rte_mbuf *mbuf = ev->mbuf;
  struct rte_hash *lookup_struct;
  struct dns_cache_item *cache;
  hash_sig_t sig;
  uint16_t dst_port;
  uint16_t offset = 0;
  uint8_t phys_q_id = evt_rsrc->evq.event_q_id[evt_rsrc->evq.nb_queues - 2];
  uint8_t virt_q_id = evt_rsrc->evq.event_q_id[evt_rsrc->evq.nb_queues - 1];
  int verdict, cache_id, ret;
  uint16_t dns_rcode;

  rte_prefetch0(rte_pktmbuf_mtod(mbuf, void *));

  if (timer_period > 0)
    __atomic_fetch_add(&rsrc->port_stats[mbuf->port].rx, 1, __ATOMIC_RELAXED);

  /* Filter the packets we want */
  verdict = resolvi_l3_verdict(rsrc, mbuf, &info);
  if (verdict != CONTINUE) goto TX;
  verdict = resolvi_l4_verdict(rsrc, mbuf, &info, true);
  if (verdict != CONTINUE) goto TX;
  verdict = resolvi_l7_verdict(rsrc, mbuf, &info, true);
  if (verdict != CONTINUE) goto TX;

  lookup_struct = get_resolvi_cache_lookup_struct(socket_id);

  sig = rte_hash_hash(lookup_struct, (const void *)*info.dns_name);
  printf("sig: %" PRIu32 "\n", sig);

  cache_id = rte_hash_lookup_with_hash(lookup_struct,
                                       (const void *)*info.dns_name, sig);
  printf("cache_id: %d\n", cache_id);
  fflush(stdout);
  if (cache_id < 0) {
    verdict = PKT_PASS;
    goto TX;
  }

  cache = get_resolvi_cache(socket_id, cache_id);
  if (cache == NULL) {
    verdict = PKT_PASS;
    goto TX;
  }
  printf("got cache: %p\n", cache);

  if (cache->until < rte_rdtsc()) {
    rte_hash_del_key_with_hash(lookup_struct, (const void *)*info.dns_name,
                               sig);
    del_resolvi_cache(socket_id, cache_id);
    rte_mempool_put(rsrc->dns_cache_pool, cache);
    verdict = PKT_PASS;
    goto TX;
  }

  verdict = resolvi_reverse_pkt(rsrc, mbuf, &info, cache);

TX:
  printf("\n");
  fflush(stdout);
  if (info.dns_name != NULL)
    rte_mempool_put(rsrc->dns_label_pool, info.dns_name);
  info.dns_name = NULL;

  /* CONTINUE defaults to TX */
  if (verdict == CONTINUE) verdict = PKT_TX;

  /* Send to the pair port. */
  if (verdict != PKT_TX) mbuf->port = rsrc->port_info[mbuf->port].pair_port;

  if (flags & RESOLVI_EVENT_UPDT_MAC && verdict == PKT_TX)
    resolvi_mac_updating(mbuf, dst_port, &rsrc->eth_addr[dst_port]);

  if (flags & RESOLVI_EVENT_TX_ENQ) {
    if (verdict == PKT_TX)
      ev->queue_id = phys_q_id;
    else
      ev->queue_id = virt_q_id;
    ev->op = RTE_EVENT_OP_FORWARD;
    /* The adapter only have a single queue. */
    rte_event_eth_tx_adapter_txq_set(mbuf, 0);
  }

  // TODO: Fix
  if (flags & RESOLVI_EVENT_TX_DIRECT)
    rte_event_eth_tx_adapter_txq_set(mbuf, 0);

  if (timer_period > 0)
    __atomic_fetch_add(&rsrc->port_stats[mbuf->port].tx, 1, __ATOMIC_RELAXED);
}

static __rte_always_inline void resolvi_event_virt_handle(
    struct resolvi_resources *rsrc, struct rte_event *ev,
    struct resolvi_event_resources *evt_rsrc, const uint64_t timer_period,
    const uint32_t flags, const int socket_id) {
  struct resolvi_pkt_info info = {
      .cur_off = 0,
  };
  struct rte_mbuf *mbuf = ev->mbuf;
  struct rte_hash *lookup_struct;
  struct rte_net_hdr_lens hdr_lens;
  struct dns_cache_item *cache;
  hash_sig_t sig;
  uint16_t dst_port;
  uint16_t rcode;
  uint8_t phys_q_id = evt_rsrc->evq.event_q_id[evt_rsrc->evq.nb_queues - 2];
  uint8_t virt_q_id = evt_rsrc->evq.event_q_id[evt_rsrc->evq.nb_queues - 1];
  uint32_t hdrlen, ptype;
  int verdict, cache_id, ret;

  /* For virtio driver, it is possbile that ptype is not set. */
  if (mbuf->packet_type == 0) {
    ptype = rte_net_get_ptype(mbuf, &hdr_lens, RTE_PTYPE_ALL_MASK);
    mbuf->packet_type = ptype;
  }

  rte_prefetch0(rte_pktmbuf_mtod(mbuf, void *));

  if (timer_period > 0)
    __atomic_fetch_add(&rsrc->port_stats[mbuf->port].rx, 1, __ATOMIC_RELAXED);

  /* Filter the packets we want */
  verdict = resolvi_l3_verdict(rsrc, mbuf, &info);
  if (verdict != CONTINUE) goto TX;
  verdict = resolvi_l4_verdict(rsrc, mbuf, &info, false);
  if (verdict != CONTINUE) goto TX;
  verdict = resolvi_l7_verdict(rsrc, mbuf, &info, false);
  if (verdict != CONTINUE) goto TX;

  /* Doing a lookup in the cache */
  lookup_struct = get_resolvi_cache_lookup_struct(socket_id);

  sig = rte_hash_hash(lookup_struct, (const void *)*info.dns_name);
  printf("sig: %" PRIu32 "\n", sig);

  cache_id = rte_hash_lookup_with_hash(lookup_struct,
                                       (const void *)*info.dns_name, sig);
  printf("lookup cache_id: %d\n", cache_id);
  if (cache_id < 0 && cache_id != -ENOENT) {
    verdict = PKT_PASS;
    goto TX;
  }
  cache = get_resolvi_cache(socket_id, cache_id);

  /* Add a new entry to the cache */
  if (cache_id < 0) {
    cache_id = rte_hash_add_key_with_hash(lookup_struct,
                                          (const void *)*info.dns_name, sig);
    printf("add cache_id: %d\n", cache_id);
    if (cache_id < 0) {
      verdict = PKT_PASS;
      goto TX;
    }

    cache = rte_zmalloc("dns_cache_item", sizeof(struct dns_cache_item), 0);
    if (cache == NULL) {
      printf("dns_cache_item malloc failed\n");
      verdict = PKT_PASS;
      goto TX;
    }

    set_resolvi_cache(socket_id, cache_id, cache);
  } else {
    printf("got cache: %p", cache);
  }

  /* Update the cache */
  rcode = info.dns_hdr->flags | DNS_RCODE_MASK;
  cache->type = rcode == DNS_RCODE_SUCCESS    ? DNS_CACHE_POSITIVE
                : rcode == DNS_RCODE_NXDOMAIN ? DNS_CACHE_NXDOMAIN
                                              : DNS_CACHE_RCODE;
  // TODO: Setting a valid TTL require us to further process the response.
  cache->until = rte_get_timer_cycles() + CACHE_TTL_MAX_HZ;
  rte_memcpy(cache->full_packet, info.dns_hdr,
             RTE_MAX(info.dns_len, DNS_PACKET_UNICAST_SIZE_MAX));

TX:
  printf("\n");
  fflush(stdout);

  if (info.dns_name != NULL)
    rte_mempool_put(rsrc->dns_label_pool, info.dns_name);
  info.dns_name = NULL;

  /* CONTINUE defaults to TX */
  if (verdict == CONTINUE) verdict = PKT_TX;

  /* Send to the pair port. */
  if (verdict != PKT_TX) mbuf->port = rsrc->port_info[mbuf->port].pair_port;

  if (flags & RESOLVI_EVENT_UPDT_MAC && verdict == PKT_TX)
    resolvi_mac_updating(mbuf, dst_port, &rsrc->eth_addr[dst_port]);

  if (flags & RESOLVI_EVENT_TX_ENQ) {
    if (verdict == PKT_TX)
      ev->queue_id = phys_q_id;
    else
      ev->queue_id = virt_q_id;
    ev->op = RTE_EVENT_OP_FORWARD;
    /* The adapter only have a single queue. */
    rte_event_eth_tx_adapter_txq_set(mbuf, 0);
  }

  // TODO: Fix
  if (flags & RESOLVI_EVENT_TX_DIRECT)
    rte_event_eth_tx_adapter_txq_set(mbuf, 0);

  if (timer_period > 0)
    __atomic_fetch_add(&rsrc->port_stats[mbuf->port].tx, 1, __ATOMIC_RELAXED);
}

static __rte_always_inline void resolvi_event_loop_single(
    struct resolvi_resources *rsrc, const uint32_t flags) {
  struct resolvi_event_resources *evt_rsrc = rsrc->evt_rsrc;
  const uint8_t tx_q_id = evt_rsrc->evq.event_q_id[evt_rsrc->evq.nb_queues - 1];
  const uint64_t timer_period = rsrc->timer_period;
  const uint8_t event_d_id = evt_rsrc->event_d_id;
  const int port_id = resolvi_get_free_event_port(evt_rsrc);
  const int socket_id = rte_event_dev_socket_id(event_d_id);
  uint8_t enq = 0, deq = 0;
  struct rte_event ev;

  if (port_id < 0) return;
  if (socket_id < 0) return;

  printf("%s(): entering eventdev main loop on lcore %u\n", __func__,
         rte_lcore_id());

  while (!rsrc->force_quit) {
    /* Read packet from eventdev */
    deq = rte_event_dequeue_burst(event_d_id, port_id, &ev, 1, 0);
    if (!deq) continue;

    resolvi_event_phys_handle(rsrc, &ev, evt_rsrc, timer_period, flags,
                              socket_id);

    if (flags & RESOLVI_EVENT_TX_ENQ) {
      do {
        enq = rte_event_enqueue_burst(event_d_id, port_id, &ev, 1);
      } while (!enq && !rsrc->force_quit);
    }

    if (flags & RESOLVI_EVENT_TX_DIRECT) {
      do {
        enq = rte_event_eth_tx_adapter_enqueue(event_d_id, port_id, &ev, 1, 0);
      } while (!enq && !rsrc->force_quit);
    }
  }

  resolvi_event_worker_cleanup(event_d_id, port_id, &ev, enq, deq, 0);
}

static __rte_always_inline void resolvi_event_loop_burst(
    struct resolvi_resources *rsrc, const uint32_t flags) {
  struct resolvi_event_resources *evt_rsrc = rsrc->evt_rsrc;
  const uint8_t tx_q_id = evt_rsrc->evq.event_q_id[evt_rsrc->evq.nb_queues - 1];
  const uint64_t timer_period = rsrc->timer_period;
  const uint8_t event_d_id = evt_rsrc->event_d_id;
  const uint8_t deq_len = evt_rsrc->deq_depth;
  const int port_id = resolvi_get_free_event_port(evt_rsrc);
  const int socket_id = rte_event_dev_socket_id(event_d_id);
  struct rte_event ev[MAX_PKT_BURST];
  uint16_t nb_rx = 0, nb_tx = 0;
  uint8_t i;

  if (port_id < 0) return;
  if (socket_id < 0) return;

  while (!rsrc->force_quit) {
    /* Read packet from eventdev. 8< */
    nb_rx = rte_event_dequeue_burst(event_d_id, port_id, ev, deq_len, 1);
    if (nb_rx == 0) continue;

    for (i = 0; i < nb_rx; i++) {
      fflush(stdout);
      if (ev[i].sub_event_type == RESOLVI_EVENT_SUBTYPE_PHYS_PORT)
        resolvi_event_phys_handle(rsrc, &ev[i], evt_rsrc, timer_period, flags,
                                  socket_id);
      if (ev[i].sub_event_type == RESOLVI_EVENT_SUBTYPE_VIRT_PORT)
        resolvi_event_virt_handle(rsrc, &ev[i], evt_rsrc, timer_period, flags,
                                  socket_id);
    }
    /* >8 End of reading packets from eventdev. */

    if (flags & RESOLVI_EVENT_TX_ENQ) {
      /*Forwarding to destination ports. 8< */
      nb_tx = rte_event_enqueue_burst(event_d_id, port_id, ev, nb_rx);
      while (nb_tx < nb_rx && !rsrc->force_quit) {
        nb_tx += rte_event_enqueue_burst(event_d_id, port_id, ev + nb_tx,
                                         nb_tx - nb_tx);
      }
      /* >8 End of forwarding to destination ports. */
    }

    if (flags & RESOLVI_EVENT_TX_DIRECT) {
      nb_tx =
          rte_event_eth_tx_adapter_enqueue(event_d_id, port_id, ev, nb_rx, 0);
      while (nb_tx < nb_rx && !rsrc->force_quit)
        nb_tx += rte_event_eth_tx_adapter_enqueue(event_d_id, port_id,
                                                  ev + nb_tx, nb_tx - nb_tx, 0);
    }
  }

  resolvi_event_worker_cleanup(event_d_id, port_id, ev, nb_tx, nb_rx, 0);
}

static __rte_always_inline void resolvi_event_loop(
    struct resolvi_resources *rsrc, const uint32_t flags) {
  if (flags & RESOLVI_EVENT_SINGLE) resolvi_event_loop_single(rsrc, flags);
  if (flags & RESOLVI_EVENT_BURST) resolvi_event_loop_burst(rsrc, flags);
}

static void __rte_noinline
resolvi_event_main_loop_tx_d(struct resolvi_resources *rsrc) {
  resolvi_event_loop(rsrc, RESOLVI_EVENT_TX_DIRECT | RESOLVI_EVENT_SINGLE);
}

static void __rte_noinline
resolvi_event_main_loop_tx_d_brst(struct resolvi_resources *rsrc) {
  resolvi_event_loop(rsrc, RESOLVI_EVENT_TX_DIRECT | RESOLVI_EVENT_BURST);
}

static void __rte_noinline
resolvi_event_main_loop_tx_q(struct resolvi_resources *rsrc) {
  resolvi_event_loop(rsrc, RESOLVI_EVENT_TX_ENQ | RESOLVI_EVENT_SINGLE);
}

static void __rte_noinline
resolvi_event_main_loop_tx_q_brst(struct resolvi_resources *rsrc) {
  resolvi_event_loop(rsrc, RESOLVI_EVENT_TX_ENQ | RESOLVI_EVENT_BURST);
}

static void __rte_noinline
resolvi_event_main_loop_tx_d_mac(struct resolvi_resources *rsrc) {
  resolvi_event_loop(rsrc, RESOLVI_EVENT_UPDT_MAC | RESOLVI_EVENT_TX_DIRECT |
                               RESOLVI_EVENT_SINGLE);
}

static void __rte_noinline
resolvi_event_main_loop_tx_d_brst_mac(struct resolvi_resources *rsrc) {
  resolvi_event_loop(rsrc, RESOLVI_EVENT_UPDT_MAC | RESOLVI_EVENT_TX_DIRECT |
                               RESOLVI_EVENT_BURST);
}

static void __rte_noinline
resolvi_event_main_loop_tx_q_mac(struct resolvi_resources *rsrc) {
  resolvi_event_loop(rsrc, RESOLVI_EVENT_UPDT_MAC | RESOLVI_EVENT_TX_ENQ |
                               RESOLVI_EVENT_SINGLE);
}

static void __rte_noinline
resolvi_event_main_loop_tx_q_brst_mac(struct resolvi_resources *rsrc) {
  resolvi_event_loop(rsrc, RESOLVI_EVENT_UPDT_MAC | RESOLVI_EVENT_TX_ENQ |
                               RESOLVI_EVENT_BURST);
}

static __rte_always_inline void resolvi_event_vector_fwd(
    struct resolvi_resources *rsrc, struct rte_event_vector *vec,
    const uint64_t timer_period, const uint32_t flags) {
  struct rte_mbuf **mbufs = vec->mbufs;
  uint16_t i, j;

  rte_prefetch0(rte_pktmbuf_mtod(mbufs[0], void *));

  /* If vector attribute is valid, mbufs will be from same port/queue */
  if (vec->attr_valid) {
    // mbufs[i]->port = rsrc->dst_ports[mbufs[i]->port];
    vec->port = mbufs[0]->port;
    if (flags & RESOLVI_EVENT_TX_DIRECT) vec->queue = 0;

    if (timer_period > 0)
      __atomic_fetch_add(&rsrc->port_stats[mbufs[0]->port].rx, vec->nb_elem,
                         __ATOMIC_RELAXED);

    for (i = 0, j = 1; i < vec->nb_elem; i++, j++) {
      if (j < vec->nb_elem) rte_prefetch0(rte_pktmbuf_mtod(mbufs[j], void *));
      if (flags & RESOLVI_EVENT_UPDT_MAC) {
        resolvi_mac_updating(mbufs[i], vec->port, &rsrc->eth_addr[vec->port]);
      }
    }

    if (timer_period > 0)
      __atomic_fetch_add(&rsrc->port_stats[vec->port].tx, vec->nb_elem,
                         __ATOMIC_RELAXED);
  } else {
    for (i = 0, j = 1; i < vec->nb_elem; i++, j++) {
      if (timer_period > 0)
        __atomic_fetch_add(&rsrc->port_stats[mbufs[i]->port].rx, 1,
                           __ATOMIC_RELAXED);

      if (j < vec->nb_elem) rte_prefetch0(rte_pktmbuf_mtod(mbufs[j], void *));

      // mbufs[i]->port = rsrc->dst_ports[mbufs[i]->port];

      if (flags & RESOLVI_EVENT_UPDT_MAC) {
        resolvi_mac_updating(mbufs[i], vec->port, &rsrc->eth_addr[vec->port]);
      }

      if (flags & RESOLVI_EVENT_TX_DIRECT)
        rte_event_eth_tx_adapter_txq_set(mbufs[i], 0);

      if (timer_period > 0)
        __atomic_fetch_add(&rsrc->port_stats[mbufs[i]->port].tx, 1,
                           __ATOMIC_RELAXED);
    }
  }
}

static __rte_always_inline void resolvi_event_loop_vector(
    struct resolvi_resources *rsrc, const uint32_t flags) {
  struct resolvi_event_resources *evt_rsrc = rsrc->evt_rsrc;
  const int port_id = resolvi_get_free_event_port(evt_rsrc);
  const uint8_t tx_q_id = evt_rsrc->evq.event_q_id[evt_rsrc->evq.nb_queues - 1];
  const uint64_t timer_period = rsrc->timer_period;
  const uint8_t event_d_id = evt_rsrc->event_d_id;
  const uint8_t deq_len = evt_rsrc->deq_depth;
  struct rte_event ev[MAX_PKT_BURST];
  uint8_t nb_rx = 0, nb_tx = 0;
  uint8_t i;

  if (port_id < 0) return;

  printf("%s(): entering eventdev main loop on lcore %u\n", __func__,
         rte_lcore_id());

  while (!rsrc->force_quit) {
    /* Read packet from eventdev */
    nb_rx = rte_event_dequeue_burst(event_d_id, port_id, ev, deq_len, 0);
    if (!nb_rx) continue;

    for (i = 0; i < nb_rx; i++) {
      if (flags & RESOLVI_EVENT_TX_ENQ) {
        ev[i].queue_id = tx_q_id;
        ev[i].op = RTE_EVENT_OP_FORWARD;
      }

      resolvi_event_vector_fwd(rsrc, ev[i].vec, timer_period, flags);
    }

    if (flags & RESOLVI_EVENT_TX_ENQ) {
      nb_tx = rte_event_enqueue_burst(event_d_id, port_id, ev, nb_rx);
      while (nb_tx < nb_rx && !rsrc->force_quit)
        nb_tx += rte_event_enqueue_burst(event_d_id, port_id, ev + nb_tx,
                                         nb_rx - nb_tx);
    }

    if (flags & RESOLVI_EVENT_TX_DIRECT) {
      nb_tx =
          rte_event_eth_tx_adapter_enqueue(event_d_id, port_id, ev, nb_rx, 0);
      while (nb_tx < nb_rx && !rsrc->force_quit)
        nb_tx += rte_event_eth_tx_adapter_enqueue(event_d_id, port_id,
                                                  ev + nb_tx, nb_rx - nb_tx, 0);
    }
  }

  resolvi_event_worker_cleanup(event_d_id, port_id, ev, nb_tx, nb_rx, 1);
}

static void __rte_noinline
resolvi_event_main_loop_tx_d_vec(struct resolvi_resources *rsrc) {
  resolvi_event_loop_vector(rsrc, RESOLVI_EVENT_TX_DIRECT);
}

static void __rte_noinline
resolvi_event_main_loop_tx_d_brst_vec(struct resolvi_resources *rsrc) {
  resolvi_event_loop_vector(rsrc, RESOLVI_EVENT_TX_DIRECT);
}

static void __rte_noinline
resolvi_event_main_loop_tx_q_vec(struct resolvi_resources *rsrc) {
  resolvi_event_loop_vector(rsrc, RESOLVI_EVENT_TX_ENQ);
}

static void __rte_noinline
resolvi_event_main_loop_tx_q_brst_vec(struct resolvi_resources *rsrc) {
  resolvi_event_loop_vector(rsrc, RESOLVI_EVENT_TX_ENQ);
}

static void __rte_noinline
resolvi_event_main_loop_tx_d_mac_vec(struct resolvi_resources *rsrc) {
  resolvi_event_loop_vector(rsrc,
                            RESOLVI_EVENT_UPDT_MAC | RESOLVI_EVENT_TX_DIRECT);
}

static void __rte_noinline
resolvi_event_main_loop_tx_d_brst_mac_vec(struct resolvi_resources *rsrc) {
  resolvi_event_loop_vector(rsrc,
                            RESOLVI_EVENT_UPDT_MAC | RESOLVI_EVENT_TX_DIRECT);
}

static void __rte_noinline
resolvi_event_main_loop_tx_q_mac_vec(struct resolvi_resources *rsrc) {
  resolvi_event_loop_vector(rsrc,
                            RESOLVI_EVENT_UPDT_MAC | RESOLVI_EVENT_TX_ENQ);
}

static void __rte_noinline
resolvi_event_main_loop_tx_q_brst_mac_vec(struct resolvi_resources *rsrc) {
  resolvi_event_loop_vector(rsrc,
                            RESOLVI_EVENT_UPDT_MAC | RESOLVI_EVENT_TX_ENQ);
}

void resolvi_event_resource_setup(struct resolvi_resources *rsrc) {
  /* [MAC_UPDATE][TX_MODE][BURST] */
  const event_loop_cb event_loop[2][2][2][2] = {
      [0][0][0][0] = resolvi_event_main_loop_tx_d,
      [0][0][0][1] = resolvi_event_main_loop_tx_d_brst,
      [0][0][1][0] = resolvi_event_main_loop_tx_q,
      [0][0][1][1] = resolvi_event_main_loop_tx_q_brst,
      [0][1][0][0] = resolvi_event_main_loop_tx_d_mac,
      [0][1][0][1] = resolvi_event_main_loop_tx_d_brst_mac,
      [0][1][1][0] = resolvi_event_main_loop_tx_q_mac,
      [0][1][1][1] = resolvi_event_main_loop_tx_q_brst_mac,
      [1][0][0][0] = resolvi_event_main_loop_tx_d_vec,
      [1][0][0][1] = resolvi_event_main_loop_tx_d_brst_vec,
      [1][0][1][0] = resolvi_event_main_loop_tx_q_vec,
      [1][0][1][1] = resolvi_event_main_loop_tx_q_brst_vec,
      [1][1][0][0] = resolvi_event_main_loop_tx_d_mac_vec,
      [1][1][0][1] = resolvi_event_main_loop_tx_d_brst_mac_vec,
      [1][1][1][0] = resolvi_event_main_loop_tx_q_mac_vec,
      [1][1][1][1] = resolvi_event_main_loop_tx_q_brst_mac_vec,
  };
  struct resolvi_event_resources *evt_rsrc;
  uint32_t event_queue_cfg;
  int ret;

  if (!rte_event_dev_count()) rte_panic("No Eventdev found \n");

  evt_rsrc =
      rte_zmalloc("resolvi_event", sizeof(struct resolvi_event_resources), 0);
  if (evt_rsrc == NULL)
    rte_panic("Failed to allocate memory for event resources\n");

  rsrc->evt_rsrc = evt_rsrc;

  /* Setup eventdev capability callbacks */
  resolvi_event_capability_setup(evt_rsrc);

  /* Event device configuration */
  event_queue_cfg = evt_rsrc->ops.event_device_setup(rsrc);

  /* Event queue configuration */
  evt_rsrc->ops.event_queue_setup(rsrc, event_queue_cfg);

  /* Event port configuration */
  evt_rsrc->ops.event_port_setup(rsrc);

  /* Rx/Tx adapters configuration */
  evt_rsrc->ops.adapter_setup(rsrc);

  /* Start event device */
  ret = rte_event_dev_start(evt_rsrc->event_d_id);
  if (ret < 0) rte_panic("Error in starting eventdev\n");

  printf(
      "evt_vec.enabled = %d, mac_updating = %d, tx_mode_q = %d, has_burst = "
      "%d\n",
      rsrc->evt_vec.enabled, rsrc->mac_updating, evt_rsrc->tx_mode_q,
      evt_rsrc->has_burst);

  evt_rsrc->ops.resolvi_event_loop =
      event_loop[rsrc->evt_vec.enabled][rsrc->mac_updating][evt_rsrc->tx_mode_q]
                [evt_rsrc->has_burst];
}