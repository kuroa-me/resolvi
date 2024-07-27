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
#include <rte_spinlock.h>

#include "resolvi_common.h"
#include "resolvi_event.h"

static uint32_t resolvi_event_device_setup_generic(
    struct resolvi_resources *rsrc) {
  struct resolvi_event_resources *evt_rsrc = rsrc->evt_rsrc;
  /* Configures event device as per below configuration. 8< */
  struct rte_event_dev_config event_d_conf = {
      .nb_events_limit = 4096,
      .nb_event_queue_flows = 1024,
      .nb_event_port_dequeue_depth = 128,
      .nb_event_port_enqueue_depth = 128,
  };
  /* >8 End of configuration event device as per below configuration. */
  struct rte_event_dev_info dev_info;
  const uint8_t event_d_id = 0; /* Always use first event device only */
  uint32_t event_queue_cfg = 0;
  uint16_t ethdev_count = 0;
  uint16_t num_workers = 0;
  uint16_t port_id;
  int ret;

  RTE_ETH_FOREACH_DEV(port_id) {
    if (!rsrc->port_info[port_id].is_virt &&
        ((rsrc->enabled_port_mask & (1 << port_id)) == 0))
      continue;
    ethdev_count++;
  }

  /* Event device configuration */
  rte_event_dev_info_get(event_d_id, &dev_info);

  /* Enable implicit release */
  if (dev_info.event_dev_cap & RTE_EVENT_DEV_CAP_IMPLICIT_RELEASE_DISABLE)
    evt_rsrc->disable_implicit_release = 0;

  if (dev_info.event_dev_cap & RTE_EVENT_DEV_CAP_QUEUE_ALL_TYPES)
    event_queue_cfg |= RTE_EVENT_QUEUE_CFG_ALL_TYPES;

  event_d_conf.nb_event_queues =
      ethdev_count /* One queue for each ethdev port */ +
      1 /* one phys Tx adapter Single link queue */ +
      1 /* one virt Tx adapter Single link queue */;

  if (dev_info.max_event_queues < event_d_conf.nb_event_queues)
    rte_panic("Not enough event queues, %d required, %d provided\n",
              event_d_conf.nb_event_queues, dev_info.max_event_queues);

  if (dev_info.max_num_events < event_d_conf.nb_events_limit) {
    event_d_conf.nb_events_limit = dev_info.max_num_events;
  }

  if (dev_info.max_event_queue_flows < event_d_conf.nb_event_queue_flows)
    event_d_conf.nb_event_queue_flows = dev_info.max_event_queue_flows;

  if (dev_info.max_event_port_dequeue_depth <
      event_d_conf.nb_event_port_dequeue_depth)
    event_d_conf.nb_event_port_dequeue_depth =
        dev_info.max_event_port_dequeue_depth;

  if (dev_info.max_event_port_enqueue_depth <
      event_d_conf.nb_event_port_enqueue_depth)
    event_d_conf.nb_event_port_enqueue_depth =
        dev_info.max_event_port_enqueue_depth;

  /* Ignore Main core and service cores. */
  num_workers = rte_lcore_count() /* Total core count */
                - 1               /* Main core */
                - rte_service_lcore_count() /* Service core */;
  if (dev_info.max_event_ports < num_workers)
    num_workers = dev_info.max_event_ports;

  event_d_conf.nb_event_ports = num_workers;
  evt_rsrc->evp.nb_ports = num_workers;
  evt_rsrc->evq.nb_queues = event_d_conf.nb_event_queues;

  evt_rsrc->has_burst =
      !!(dev_info.event_dev_cap & RTE_EVENT_DEV_CAP_BURST_MODE);

  ret = rte_event_dev_configure(event_d_id, &event_d_conf);
  if (ret < 0) rte_panic("Error in configuring event device, err=%d\n", ret);

  evt_rsrc->event_d_id = event_d_id;
  return event_queue_cfg;
}

static void resolvi_event_queue_setup_generic(struct resolvi_resources *rsrc,
                                              uint32_t event_queue_cfg) {
  struct resolvi_event_resources *evt_rsrc = rsrc->evt_rsrc;
  uint8_t event_d_id = evt_rsrc->event_d_id;
  /* Event queue initialization. 8< */
  struct rte_event_queue_conf event_q_conf = {
      .nb_atomic_flows = 1024,
      .nb_atomic_order_sequences = 1024,
      .event_queue_cfg = event_queue_cfg,
      .priority = RTE_EVENT_DEV_PRIORITY_NORMAL,
  };
  struct rte_event_queue_conf def_q_conf;
  uint8_t event_q_id;
  int32_t ret;

  event_q_conf.schedule_type = rsrc->sched_type;
  evt_rsrc->evq.event_q_id =
      (uint8_t *)malloc(sizeof(uint8_t) * evt_rsrc->evq.nb_queues);
  if (!evt_rsrc->evq.event_q_id) rte_panic("Memory allocation failure\n");

  ret = rte_event_queue_default_conf_get(event_d_id, 0, &def_q_conf);
  if (ret < 0) rte_panic("Error to get default config of event queue\n");
  /* >8 End of event queue initialization. */

  if (def_q_conf.nb_atomic_flows < event_q_conf.nb_atomic_flows)
    event_q_conf.nb_atomic_flows = def_q_conf.nb_atomic_flows;

  /* Configure atomic queues 8< */
  for (event_q_id = 0; event_q_id < (evt_rsrc->evq.nb_queues - 2);
       event_q_id++) {
    ret = rte_event_queue_setup(event_d_id, event_q_id, &event_q_conf);
    if (ret < 0) rte_panic("Error in configuring event queue\n");
    evt_rsrc->evq.event_q_id[event_q_id] = event_q_id;
  }
  /* >8 End of configuring atomic queues. */

  /* Configure single link queue */
  event_q_conf.event_queue_cfg |= RTE_EVENT_QUEUE_CFG_SINGLE_LINK;
  event_q_conf.priority = RTE_EVENT_DEV_PRIORITY_HIGHEST;
  for (; event_q_id < (evt_rsrc->evq.nb_queues); event_q_id++) {
    ret = rte_event_queue_setup(event_d_id, event_q_id, &event_q_conf);
    if (ret < 0) rte_panic("Error in configuring event queue for Tx adapter\n");
    evt_rsrc->evq.event_q_id[event_q_id] = event_q_id;
  }
}

static void resolvi_event_port_setup_generic(struct resolvi_resources *rsrc) {
  struct resolvi_event_resources *evt_rsrc = rsrc->evt_rsrc;
  uint8_t event_d_id = evt_rsrc->event_d_id;
  /* Event port initialization. 8< */
  struct rte_event_port_conf event_p_conf = {
      .dequeue_depth = 32, .enqueue_depth = 32, .new_event_threshold = 4096};
  struct rte_event_port_conf def_p_conf;
  uint8_t event_p_id;
  int32_t ret;

  evt_rsrc->evp.event_p_id =
      (uint8_t *)malloc(sizeof(uint8_t) * evt_rsrc->evp.nb_ports);
  if (!evt_rsrc->evp.event_p_id)
    rte_panic("Failed to allocate memory for Event Ports\n");

  memset(&def_p_conf, 0, sizeof(struct rte_event_port_conf));
  ret = rte_event_port_default_conf_get(event_d_id, 0, &def_p_conf);
  if (ret < 0) rte_panic("Error to get default configuration of event port\n");

  if (def_p_conf.new_event_threshold < event_p_conf.new_event_threshold)
    event_p_conf.new_event_threshold = def_p_conf.new_event_threshold;

  if (def_p_conf.dequeue_depth < event_p_conf.dequeue_depth)
    event_p_conf.dequeue_depth = def_p_conf.dequeue_depth;

  if (def_p_conf.enqueue_depth < event_p_conf.enqueue_depth)
    event_p_conf.enqueue_depth = def_p_conf.enqueue_depth;

  event_p_conf.event_port_cfg = 0;
  if (evt_rsrc->disable_implicit_release)
    event_p_conf.event_port_cfg |= RTE_EVENT_PORT_CFG_DISABLE_IMPL_REL;

  evt_rsrc->deq_depth = def_p_conf.dequeue_depth;

  for (event_p_id = 0; event_p_id < evt_rsrc->evp.nb_ports; event_p_id++) {
    /* Setting up event ports */
    ret = rte_event_port_setup(event_d_id, event_p_id, &event_p_conf);
    if (ret < 0) rte_panic("Error in configuring event port %d\n", event_p_id);

    /* Linking worker ports to atomic queues, exculde last singlelink queue */
    ret = rte_event_port_link(event_d_id, event_p_id, evt_rsrc->evq.event_q_id,
                              NULL, evt_rsrc->evq.nb_queues - 2);
    if (ret != (evt_rsrc->evq.nb_queues - 2))
      rte_panic("Error in linking event port %d to queues\n", event_p_id);
    evt_rsrc->evp.event_p_id[event_p_id] = event_p_id;
    /* >8 End of event port initialization. */
  }
  /* init spinlock */
  rte_spinlock_init(&evt_rsrc->evp.lock);

  evt_rsrc->def_p_conf = event_p_conf;
}

static void resolvi_rx_tx_adapter_setup_generic(
    struct resolvi_resources *rsrc) {
  struct resolvi_event_resources *evt_rsrc = rsrc->evt_rsrc;
  struct rte_event_eth_rx_adapter_queue_conf eth_q_conf;
  uint8_t event_d_id = evt_rsrc->event_d_id;
  uint8_t phys_rx_adptr_id = 0;
  uint8_t virt_rx_adptr_id = 1;
  uint8_t phys_tx_adptr_id = 0;
  uint8_t virt_tx_adptr_id = 1;
  uint8_t tx_port_id = 0;
  uint16_t port_id;
  uint32_t service_id;
  int32_t ret, i = 0;
  bool is_virt = false;
  uint8_t rx_adptr_id = 0, tx_adptr_id = 0;

  memset(&eth_q_conf, 0, sizeof(eth_q_conf));
  eth_q_conf.ev.priority = RTE_EVENT_DEV_PRIORITY_NORMAL;

  /* Rx adapter setup */
  evt_rsrc->rx_adptr.nb_rx_adptr =
      1 /* Physical port */ + 1 /* Virtio_user port */;
  evt_rsrc->rx_adptr.rx_adptr =
      (uint8_t *)malloc(sizeof(uint8_t) * evt_rsrc->rx_adptr.nb_rx_adptr);
  evt_rsrc->rx_adptr.service_id =
      (uint32_t *)malloc(sizeof(uint32_t) * evt_rsrc->rx_adptr.nb_rx_adptr);
  if (!evt_rsrc->rx_adptr.rx_adptr || !evt_rsrc->rx_adptr.service_id) {
    free(evt_rsrc->evp.event_p_id);
    free(evt_rsrc->evq.event_q_id);
    rte_panic("Failed to allocate memery for Rx adapter\n");
  }

  ret = rte_event_eth_rx_adapter_create(phys_rx_adptr_id, event_d_id,
                                        &evt_rsrc->def_p_conf);
  if (ret) rte_panic("Failed to create physical Rx adapter\n");

  ret = rte_event_eth_rx_adapter_create(virt_rx_adptr_id, event_d_id,
                                        &evt_rsrc->def_p_conf);
  if (ret) rte_panic("Failed to create virtio_user Rx adapter\n");

  /* Configure user requested sched type */
  eth_q_conf.ev.sched_type = rsrc->sched_type;
  RTE_ETH_FOREACH_DEV(port_id) {
    is_virt = rsrc->port_info[port_id].is_virt;
    if (!is_virt && ((rsrc->enabled_port_mask & (1 << port_id)) == 0)) continue;
    eth_q_conf.ev.queue_id = evt_rsrc->evq.event_q_id[i];
    if (rsrc->evt_vec.enabled) {
      uint32_t cap;

      if (rte_event_eth_rx_adapter_caps_get(event_d_id, port_id, &cap))
        rte_panic("Failed to get event rx adapter capability");

      if (cap & RTE_EVENT_ETH_RX_ADAPTER_CAP_EVENT_VECTOR) {
        eth_q_conf.vector_sz = rsrc->evt_vec.size;
        eth_q_conf.vector_timeout_ns = rsrc->evt_vec.timeout_ns;
        eth_q_conf.vector_mp = rsrc->evt_vec_pool;
        eth_q_conf.rx_queue_flags |=
            RTE_EVENT_ETH_RX_ADAPTER_QUEUE_EVENT_VECTOR;
      } else {
        rte_panic("Rx adapter doesn't support event vector");
      }
    }

    eth_q_conf.ev.sub_event_type = is_virt ? RESOLVI_EVENT_SUBTYPE_VIRT_PORT
                                           : RESOLVI_EVENT_SUBTYPE_PHYS_PORT;
    rx_adptr_id = is_virt ? virt_rx_adptr_id : phys_rx_adptr_id;
    ret = rte_event_eth_rx_adapter_queue_add(rx_adptr_id, port_id, -1,
                                             &eth_q_conf);
    if (ret)
      rte_panic("Failed to add %s queues to Rx adapter, errno=%s\n",
                is_virt ? "virtio" : "physical", rte_strerror(ret));
    if (i < evt_rsrc->evq.nb_queues) i++;
  }

  for (rx_adptr_id = 0; rx_adptr_id < 2; rx_adptr_id++) {
    ret = rte_event_eth_rx_adapter_service_id_get(rx_adptr_id, &service_id);
    if (ret != -ESRCH && ret != 0)
      rte_panic("Error getting the service ID for rx adptr\n");

    rte_service_runstate_set(service_id, 1);
    rte_service_set_runstate_mapped_check(service_id, 0);
    evt_rsrc->rx_adptr.service_id[rx_adptr_id] = service_id;

    ret = rte_event_eth_rx_adapter_start(rx_adptr_id);
    if (ret)
      rte_panic("Rx adapter[%d] start Failed\n", rx_adptr_id);
    else
      printf("Rx adapter[%d] service_id[%d] started\n", rx_adptr_id,
             service_id);

    evt_rsrc->rx_adptr.rx_adptr[rx_adptr_id] = rx_adptr_id;
  }

  /* Tx adapter setup */
  evt_rsrc->tx_adptr.nb_tx_adptr =
      1 /* Physical port */ + 1 /* Virtio_user port */;
  evt_rsrc->tx_adptr.tx_adptr =
      (uint8_t *)malloc(sizeof(uint8_t) * evt_rsrc->tx_adptr.nb_tx_adptr);
  evt_rsrc->tx_adptr.service_id =
      (uint32_t *)malloc(sizeof(uint32_t) * evt_rsrc->tx_adptr.nb_tx_adptr);
  if (!evt_rsrc->tx_adptr.tx_adptr || !evt_rsrc->tx_adptr.service_id) {
    free(evt_rsrc->rx_adptr.rx_adptr);
    free(evt_rsrc->rx_adptr.service_id);
    free(evt_rsrc->evp.event_p_id);
    free(evt_rsrc->evq.event_q_id);
    rte_panic("Failed to allocate memery for Rx adapter\n");
  }

  ret = rte_event_eth_tx_adapter_create(phys_tx_adptr_id, event_d_id,
                                        &evt_rsrc->def_p_conf);
  if (ret) rte_panic("Failed to create physical tx adapter\n");

  ret = rte_event_eth_tx_adapter_create(virt_tx_adptr_id, event_d_id,
                                        &evt_rsrc->def_p_conf);
  if (ret) rte_panic("Failed to create virtio_user tx adapter\n");

  RTE_ETH_FOREACH_DEV(port_id) {
    is_virt = rsrc->port_info[port_id].is_virt;
    if (!is_virt && ((rsrc->enabled_port_mask & (1 << port_id)) == 0)) continue;

    tx_adptr_id = is_virt ? virt_tx_adptr_id : phys_tx_adptr_id;
    ret = rte_event_eth_tx_adapter_queue_add(tx_adptr_id, port_id, -1);
    printf("Added queue[%d] to tx adapter[%d]\n", port_id, tx_adptr_id);
    if (ret) rte_panic("Failed to add queues to Tx adapter\n");
  }

  for (tx_adptr_id = 0; tx_adptr_id < 2; tx_adptr_id++) {
    ret = rte_event_eth_tx_adapter_service_id_get(tx_adptr_id, &service_id);
    if (ret != -ESRCH && ret != 0)
      rte_panic("Failed to get Tx adapter service ID\n");

    rte_service_runstate_set(service_id, 1);
    rte_service_set_runstate_mapped_check(service_id, 0);
    evt_rsrc->tx_adptr.service_id[tx_adptr_id] = service_id;

    /* Extra port created. 8< */
    ret = rte_event_eth_tx_adapter_event_port_get(tx_adptr_id, &tx_port_id);
    if (ret) rte_panic("Failed to get Tx adapter port id: %d\n", tx_adptr_id);

    //? Link single link to the tx port?
    ret = rte_event_port_link(
        event_d_id, tx_port_id,
        &evt_rsrc->evq.event_q_id[evt_rsrc->evq.nb_queues - 2 + tx_adptr_id],
        NULL, 1);
    if (ret != 1)
      rte_panic("Unable to link Tx adapter port %d to Tx queue:err=%d\n",
                evt_rsrc->evq.nb_queues - 2 + tx_adptr_id, ret);
    printf("Linked Tx adapter port %d to Tx queue %d\n", tx_port_id,
           evt_rsrc->evq.event_q_id[evt_rsrc->evq.nb_queues - 2 + tx_adptr_id]);
    /* >8 End of extra port created. */

    ret = rte_event_eth_tx_adapter_start(tx_adptr_id);
    if (ret)
      rte_panic("Tx adapter[%d] start Failed\n", tx_adptr_id);
    else
      printf("Tx adapter[%d] service_id[%d] started\n", tx_adptr_id,
             service_id);

    evt_rsrc->tx_adptr.tx_adptr[tx_adptr_id] = tx_adptr_id;
  }
}

void resolvi_event_set_generic_ops(struct event_setup_ops *ops) {
  ops->event_device_setup = resolvi_event_device_setup_generic;
  ops->event_queue_setup = resolvi_event_queue_setup_generic;
  ops->event_port_setup = resolvi_event_port_setup_generic;
  ops->adapter_setup = resolvi_rx_tx_adapter_setup_generic;
}