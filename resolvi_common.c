#include "resolvi_common.h"

int resolvi_create_virtio_user_ports(struct resolvi_resources *rsrc) {
  uint16_t nb_ports = rte_eth_dev_count_avail();
  uint16_t nb_virt_ports = 0;
  uint16_t port_id;

  int ret;

  RTE_ETH_FOREACH_DEV(port_id) {
    char portname[32];
    char portargs[256];
    struct rte_ether_addr addr = {0};
    uint16_t virt_port_id;

    /* once we have created a virtio port for each physical port, stop */
    if (++nb_virt_ports > nb_ports) break;

    /* skip physical ports that are not enabled */
    if ((rsrc->enabled_port_mask & (1 << port_id)) == 0) {
      printf("Skipping create paired port for port %u\n", port_id);
      continue;
    }

    /* get MAC address of physical port to use as MAC of virtio_user port */
    rte_eth_macaddr_get(port_id, &addr);

    /* set the name and arguments */
    snprintf(portname, sizeof(portname), "virtio_user%u", port_id);
    snprintf(
        portargs, sizeof(portargs),
        "path=/dev/"
        "vhost-net,queues=1,queue_size=%u,iface=%s,mac=" RTE_ETHER_ADDR_PRT_FMT,
        RX_DESC_DEFAULT, portname, RTE_ETHER_ADDR_BYTES(&addr));

    printf("Creating virtio_user port %s with args %s\n", portname, portargs);
    fflush(stdout);

    if (rte_eal_hotplug_add("vdev", portname, portargs) < 0)
      rte_panic("cannot create virtio_user port");

    /* get the virtio_user port id */
    if (rte_eth_dev_get_port_by_name(portname, &virt_port_id) != 0) {
      rte_eal_hotplug_remove("vdev", portname);
      rte_panic("cannot find added virtio_user port %s", portname);
    }

    /* Insert phys virt pair into port_info */
    rsrc->port_info[port_id].pair_port = virt_port_id;
    rsrc->port_info[virt_port_id].pair_port = port_id;
    rsrc->port_info[port_id].is_virt = false;
    rsrc->port_info[virt_port_id].is_virt = true;
  }

  return --nb_virt_ports;
}

int resolvi_event_init_ports(struct resolvi_resources *rsrc) {
  uint16_t nb_rxd = RX_DESC_DEFAULT;
  uint16_t nb_txd = TX_DESC_DEFAULT;
  struct rte_eth_conf port_conf = {
      .txmode =
          {
              .mq_mode = RTE_ETH_MQ_TX_NONE,
              .offloads = RTE_ETH_TX_OFFLOAD_UDP_CKSUM,
          },
      .rxmode =
          {
              .offloads = RTE_ETH_RX_OFFLOAD_UDP_CKSUM,
          },
  };
  uint16_t nb_ports_available = 0;
  uint16_t port_id;
  int ret;

  /* Initialize each port */
  RTE_ETH_FOREACH_DEV(port_id) {
    struct rte_eth_conf local_port_conf = port_conf;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;
    bool is_virt = rsrc->port_info[port_id].is_virt;

    /* skip ports that are not enabled */
    if (!is_virt && ((rsrc->enabled_port_mask & (1 << port_id))) == 0) {
      printf("Skipping disabled port %u\n", port_id);
      continue;
    }
    nb_ports_available++;

    /* init port */
    printf("Initializing port %u...", port_id);
    fflush(stdout);

    /* Virtio ports does not support RSS. */
    if (!is_virt && rsrc->event_mode) {
      local_port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
      local_port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
      local_port_conf.rx_adv_conf.rss_conf.rss_hf = RTE_ETH_RSS_IP;
    }

    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret != 0)
      rte_panic("Error during getting device (port %u) info: %s\n", port_id,
                strerror(-ret));
    local_port_conf.rx_adv_conf.rss_conf.rss_hf &=
        dev_info.flow_type_rss_offloads;
    if (local_port_conf.rx_adv_conf.rss_conf.rss_hf !=
        port_conf.rx_adv_conf.rss_conf.rss_hf) {
      printf(
          "Port %u modified RSS hash function based on hardware support, "
          "requested:%#" PRIx64 " configured:%#" PRIx64 "",
          port_id, port_conf.rx_adv_conf.rss_conf.rss_hf,
          local_port_conf.rx_adv_conf.rss_conf.rss_hf);
    }

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
      local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    }
    /* Configure the number of queues for a port. 8< */
    ret = rte_eth_dev_configure(port_id, 1, 1, &local_port_conf);
    if (ret < 0)
      rte_panic("Cannot configure device: err=%d, port=%u\n", ret, port_id);
    /* >8 End of configureation of the number of queues of a port. */

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
    if (ret < 0)
      rte_panic("Cannot adjust number of descriptors: err=%d, port=%u\n", ret,
                port_id);

    ret = rte_eth_macaddr_get(port_id, &rsrc->eth_addr[port_id]);
    if (ret < 0)
      rte_panic("Cannot get MAC address: err=%d, port=%u\n", ret, port_id);

    /* init one Rx queue */
    fflush(stdout);
    rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = local_port_conf.rxmode.offloads;
    /* Using lcore to poll one or serveral ports. 8< */
    ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd,
                                 rte_eth_dev_socket_id(port_id), &rxq_conf,
                                 rsrc->pktmbuf_pool);
    if (ret < 0)
      rte_panic("rte_eth_rx_queue_setup: err=%d, port=%u\n", ret, port_id);
    /* >8 End of using lcore to poll one or several ports. */

    /* Init one Tx queue on each port. 8< */
    fflush(stdout);
    txq_conf = dev_info.default_txconf;
    txq_conf.offloads = local_port_conf.txmode.offloads;
    ret = rte_eth_tx_queue_setup(port_id, 0, nb_txd,
                                 rte_eth_dev_socket_id(port_id), &txq_conf);
    if (ret < 0)
      rte_panic("rte_eth_tx_queue_setup: err=%d, port=%u\n", ret, port_id);
    /* >8 End of init one Tx queue on each port. */

    if (!is_virt && rsrc->promiscuous_on) {
      ret = rte_eth_promiscuous_enable(port_id);
      if (ret != 0)
        rte_panic("rte_eth_promiscuous_enable: err=%s, port=%u=n",
                  rte_strerror(-ret), port_id);
    }

    printf("Port %u, MAC address: " RTE_ETHER_ADDR_PRT_FMT "\n\n", port_id,
           RTE_ETHER_ADDR_BYTES(&rsrc->eth_addr[port_id]));
  }

  return nb_ports_available;
}

static void resolvi_event_vector_array_free(struct rte_event events[],
                                            uint16_t num) {
  uint16_t i;

  for (i = 0; i < num; i++) {
    rte_pktmbuf_free_bulk(&events[i].vec->mbufs[events[i].vec->elem_offset],
                          events[i].vec->nb_elem);
    rte_mempool_put(rte_mempool_from_obj(events[i].vec), events[i].vec);
  }
}

static void resolvi_event_port_flush(uint8_t event_d_id __rte_unused,
                                     struct rte_event ev,
                                     void *args __rte_unused) {
  if (ev.event_type & RTE_EVENT_TYPE_VECTOR)
    resolvi_event_vector_array_free(&ev, 1);
  else
    rte_pktmbuf_free(ev.mbuf);
}

void resolvi_event_worker_cleanup(uint8_t event_d_id, uint8_t port_id,
                                  struct rte_event events[], uint16_t nb_enq,
                                  uint16_t nb_deq, uint8_t is_vector) {
  int i;

  if (nb_deq) {
    if (is_vector)
      resolvi_event_vector_array_free(events + nb_enq, nb_deq - nb_enq);
    else
      for (i = nb_enq; i < nb_deq; i++) rte_pktmbuf_free(events[i].mbuf);

    for (i = 0; i < nb_deq; i++) events[i].op = RTE_EVENT_OP_RELEASE;
    rte_event_enqueue_burst(event_d_id, port_id, events, nb_deq);
  }

  rte_event_port_quiesce(event_d_id, port_id, resolvi_event_port_flush, NULL);
}
