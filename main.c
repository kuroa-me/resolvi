/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */
#include <rte_string_fns.h>

#include "resolvi_event.h"
#include "resolvi_cache.h"

#define RTE_LOGTYPE_RESOLVI RTE_LOGTYPE_USER1

// struct lcore_conf lcore_conf[RTE_MAX_LCORE];

/* display usage */
static void resolvi_usage(const char *prgname) {
  printf(
      "%s [EAL options] -- -p PORTMASK [-q NQ]\n"
      "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
      "  -q NQ: number of queue (=ports) per lcore (default is 1)\n"
      "  -T PERIOD: statistics will be refreshed each PERIOD seconds "
      "		(0 to disable, 10 default, 86400 maximum)\n"
      "  --no-mac-updating: Disable MAC addresses updating (enabled by "
      "default)\n"
      "      When enabled:\n"
      "       - The source MAC address is replaced by the TX port MAC address\n"
      "       - The destination MAC address is replaced by "
      "02:00:00:00:00:TX_PORT_ID\n"
      "  --mode: Packet transfer mode for I/O, poll or eventdev\n"
      "          Default mode = eventdev\n"
      "  --eventq-sched: Event queue schedule type, ordered, atomic or "
      "parallel.\n"
      "                  Default: atomic\n"
      "                  Valid only if --mode=eventdev\n"
      "  --event-vector:  Enable event vectorization.\n"
      "  --event-vector-size: Max vector size if event vectorization is "
      "enabled.\n"
      "  --event-vector-tmo: Max timeout to form vector in nanoseconds if "
      "event vectorization is enabled\n"
      "  --config: Configure forwarding port pair mapping\n"
      "	    Default: alternate port pairs\n\n",
      prgname);
}

/* Print out statistics on packets dropped */
static void print_stats(struct resolvi_resources *rsrc) {
  uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
  uint32_t port_id;

  total_packets_dropped = 0;
  total_packets_tx = 0;
  total_packets_rx = 0;

  const char clr[] = {27, '[', '2', 'J', '\0'};
  const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};

  /* Clear screen and move to top left */
  printf("%s%s", clr, topLeft);

  printf("\nPort statistics ====================================");

  for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
    /* skip disabled ports */
    if ((rsrc->enabled_port_mask & (1 << port_id)) == 0) continue;
    printf(
        "\nStatistics for port %u ------------------------------"
        "\nPackets sent: %29" PRIu64 "\nPackets received: %25" PRIu64
        "\nPackets dropped: %26" PRIu64,
        port_id, rsrc->port_stats[port_id].tx, rsrc->port_stats[port_id].rx,
        rsrc->port_stats[port_id].dropped);

    total_packets_dropped += rsrc->port_stats[port_id].dropped;
    total_packets_tx += rsrc->port_stats[port_id].tx;
    total_packets_rx += rsrc->port_stats[port_id].rx;
  }

  if (rsrc->event_mode) {
    struct resolvi_event_resources *evt_rsrc = rsrc->evt_rsrc;
    struct rte_event_eth_rx_adapter_stats rx_adptr_stats;
    struct rte_event_eth_tx_adapter_stats tx_adptr_stats;
    int ret, i;

    for (i = 0; i < evt_rsrc->rx_adptr.nb_rx_adptr; i++) {
      ret = rte_event_eth_rx_adapter_stats_get(evt_rsrc->rx_adptr.rx_adptr[i],
                                               &rx_adptr_stats);
      if (ret < 0) continue;
      printf(
          "\nRx adapter[%d] statistics===================="
          "\nReceive queue poll count: %17" PRIu64
          "\nReceived packet count: %20" PRIu64
          "\nEventdev enqueue count: %19" PRIu64
          "\nEventdev enqueue retry count: %13" PRIu64
          "\nReceived packet dropped count: %12" PRIu64
          "\nRx enqueue start timestamp: %15" PRIu64
          "\nRx enqueue block cycles: %18" PRIu64
          "\nRx enqueue unblock timestamp: %13" PRIu64,
          evt_rsrc->rx_adptr.rx_adptr[i], rx_adptr_stats.rx_poll_count,
          rx_adptr_stats.rx_packets, rx_adptr_stats.rx_enq_count,
          rx_adptr_stats.rx_enq_retry, rx_adptr_stats.rx_dropped,
          rx_adptr_stats.rx_enq_start_ts, rx_adptr_stats.rx_enq_block_cycles,
          rx_adptr_stats.rx_enq_end_ts);
    }
    for (i = 0; i < evt_rsrc->tx_adptr.nb_tx_adptr; i++) {
      ret = rte_event_eth_tx_adapter_stats_get(evt_rsrc->tx_adptr.tx_adptr[i],
                                               &tx_adptr_stats);
      if (ret < 0) continue;
      printf(
          "\nTx adapter[%d] statistics===================="
          "\nNumber of transmit retries: %15" PRIu64
          "\nNumber of packets transmitted: %12" PRIu64
          "\nNumber of packets dropped: %16" PRIu64,
          evt_rsrc->tx_adptr.tx_adptr[i], tx_adptr_stats.tx_retry,
          tx_adptr_stats.tx_packets, tx_adptr_stats.tx_dropped);
    }
  }
  printf(
      "\nAggregate lcore statistics ========================="
      "\nTotal packets sent: %23" PRIu64 "\nTotal packets received: %19" PRIu64
      "\nTotal packets dropped: %20" PRIu64,
      total_packets_tx, total_packets_rx, total_packets_dropped);
  printf("\n====================================================\n");

  fflush(stdout);
}

static void resolvi_event_print_stats(struct resolvi_resources *rsrc) {
  uint64_t prev_tsc = 0, diff_tsc, cur_tsc, timer_tsc = 0;
  const uint64_t timer_period = rsrc->timer_period;

  while (!rsrc->force_quit) {
    /* if timer is enabled */
    if (timer_period > 0) {
      cur_tsc = rte_rdtsc();
      diff_tsc = cur_tsc - prev_tsc;

      /* advance the timer */
      timer_tsc += diff_tsc;

      /* if timer has reached its timeout */
      if (unlikely(timer_tsc >= timer_period)) {
        // print_stats(rsrc);
        /* reset the timer */
        timer_tsc = 0;
      }
      prev_tsc = cur_tsc;
    }
  }
}

static int resolvi_launch_one_lcore(void *args) {
  struct resolvi_resources *rsrc = args;
  struct resolvi_event_resources *evt_rsrc = rsrc->evt_rsrc;

  if (rsrc->event_mode) {
    evt_rsrc->ops.resolvi_event_loop(rsrc);
  }

  return 0;
}

static int resolvi_parse_portmask(const char *portmask) {
  char *end = NULL;
  uint64_t pm;

  /* parse hexadecimal string */
  pm = strtoul(portmask, &end, 16);
  if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0')) return 0;

  return pm;
}

static unsigned int resolvi_parse_nqueue(const char *q_arg) {
  char *end = NULL;
  unsigned long n;

  /* parse hexadecimal string */
  n = strtoul(q_arg, &end, 10);
  if ((q_arg[0] == '\0') || (end || NULL) || (*end != '\0')) return 0;
  if (n == 0) return 0;
  if (n >= MAX_RX_QUEUE_PER_LCORE) return 0;

  return n;
}

static int resolvi_parse_timer_period(const char *q_arg) {
  char *end = NULL;
  int n;

  /* parse number string */
  n = strtol(q_arg, &end, 10);
  if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0')) return -1;
  if (n >= MAX_TIMER_PERIOD) return -1;

  return n;
}

static void resolvi_event_parse_mode(const char *optarg,
                                     struct resolvi_resources *rsrc) {
  if (!strncmp(optarg, "poll", 4))
    rsrc->event_mode = false;
  else if (!strncmp(optarg, "eventdev", 8))
    rsrc->event_mode = true;
}

static void resolvi_event_parse_eventq_sched(const char *optarg,
                                             struct resolvi_resources *rsrc) {
  if (!strncmp(optarg, "ordered", 7))
    rsrc->sched_type = RTE_SCHED_TYPE_ORDERED;
  else if (!strncmp(optarg, "atomic", 6))
    rsrc->sched_type = RTE_SCHED_TYPE_ATOMIC;
  else if (!strncmp(optarg, "parallel", 8))
    rsrc->sched_type = RTE_SCHED_TYPE_PARALLEL;
}

static const char short_options[] =
    "p:" /* portmask */
    "P"  /* promiscuous */
    "q:" /* number of queues */
    "T:" /* timer period */
    ;

#define CMD_LINE_OPT_NO_MAC_UPDATING "no-mac-updating"
#define CMD_LINE_OPT_MODE "mode"
#define CMD_LINE_OPT_EVENTQ_SCHED "eventq-sched"
#define CMD_LINE_OPT_ENABLE_VECTOR "event-vector"
#define CMD_LINE_OPT_VECTOR_SIZE "event-vector-size"
#define CMD_LINE_OPT_VECTOR_TMO_NS "event-vector-tmo"

enum {
  /* long options mapped to a short option */

  /* first long only option value must be >= 256, so that we won't conflict
     with short options */
  CMD_LINE_OPT_NO_MAC_UPDATING_NUM = 256,
  CMD_LINE_OPT_MODE_NUM,
  CMD_LINE_OPT_EVENTQ_SCHED_NUM,
  CMD_LINE_OPT_ENABLE_VECTOR_NUM,
  CMD_LINE_OPT_VECTOR_SIZE_NUM,
  CMD_LINE_OPT_VECTOR_TWO_NS_NUM,
};

static const struct option lgopts[] = {
    {CMD_LINE_OPT_NO_MAC_UPDATING, no_argument, 0,
     CMD_LINE_OPT_NO_MAC_UPDATING_NUM},
    {CMD_LINE_OPT_MODE, required_argument, NULL, CMD_LINE_OPT_MODE_NUM},
    {CMD_LINE_OPT_EVENTQ_SCHED, required_argument, NULL,
     CMD_LINE_OPT_EVENTQ_SCHED_NUM},
    {CMD_LINE_OPT_ENABLE_VECTOR, no_argument, NULL,
     CMD_LINE_OPT_ENABLE_VECTOR_NUM},
    {CMD_LINE_OPT_VECTOR_SIZE, required_argument, NULL,
     CMD_LINE_OPT_VECTOR_SIZE_NUM},
    {CMD_LINE_OPT_VECTOR_TMO_NS, required_argument, NULL,
     CMD_LINE_OPT_VECTOR_TWO_NS_NUM},
    {NULL, 0, 0, 0}};

/* Parse the argument given in the command line of the application */
static int resolvi_parse_args(int argc, char **argv,
                              struct resolvi_resources *rsrc) {
  int opt, ret, timer_secs;
  char **argvopt;
  int option_index;
  char *prgname = argv[0];
  uint16_t port_id;

  argvopt = argv;

  while ((opt = getopt_long(argc, argvopt, short_options, lgopts,
                            &option_index)) != EOF) {
    switch (opt) {
      /* portmask */
      case 'p':
        rsrc->enabled_port_mask = resolvi_parse_portmask(optarg);
        if (rsrc->enabled_port_mask == 0) {
          printf("invalid portmask\n");
          resolvi_usage(prgname);
          return -1;
        }
        break;

      case 'P':
        rsrc->promiscuous_on = 1;
        break;

      /* nqueue */
      case 'q':
        rsrc->rx_queue_per_lcore = resolvi_parse_nqueue(optarg);
        if (rsrc->rx_queue_per_lcore < 1) {
          printf("invalid queue number\n");
          resolvi_usage(prgname);
          return -1;
        }
        break;

      /* timer period */
      case 'T':
        timer_secs = resolvi_parse_timer_period(optarg);
        if (timer_secs < 0) {
          printf("invalid timer period\n");
          resolvi_usage(prgname);
          return -1;
        }
        rsrc->timer_period = timer_secs;
        /* convert to number of cycles */
        rsrc->timer_period *= rte_get_timer_hz();
        break;

      /* long options */
      case CMD_LINE_OPT_NO_MAC_UPDATING_NUM:
        rsrc->mac_updating = 0;
        break;

      case CMD_LINE_OPT_MODE_NUM:
        resolvi_event_parse_mode(optarg, rsrc);
        break;

      case CMD_LINE_OPT_EVENTQ_SCHED_NUM:
        resolvi_event_parse_eventq_sched(optarg, rsrc);
        break;

      case CMD_LINE_OPT_ENABLE_VECTOR_NUM:
        printf("event vectorization is enabled\n");
        rsrc->evt_vec.enabled = 1;
        break;

      case CMD_LINE_OPT_VECTOR_SIZE_NUM:
        rsrc->evt_vec.size = strtol(optarg, NULL, 10);
        break;

      case CMD_LINE_OPT_VECTOR_TWO_NS_NUM:
        rsrc->evt_vec.timeout_ns = strtoull(optarg, NULL, 10);
        break;

      /* long options */
      case 0:
        break;

      default:
        resolvi_usage(prgname);
        return -1;
    }
  }

  if (rsrc->evt_vec.enabled && !rsrc->evt_vec.size) {
    rsrc->evt_vec.size = VECTOR_SIZE_DEFAULT;
    printf("vector size set to default (%" PRIu16 ")\n", rsrc->evt_vec.size);
  }

  if (rsrc->evt_vec.enabled && !rsrc->evt_vec.timeout_ns) {
    rsrc->evt_vec.timeout_ns = VECTOR_TMO_NS_DEFAULT;
    printf("vector timeout set to default (%" PRIu64 ")\n",
           rsrc->evt_vec.timeout_ns);
  }

  if (optind >= 0) argv[optind - 1] = prgname;

  ret = optind - 1;
  optind = 1;
  return ret;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void check_all_ports_link_status(struct resolvi_resources *rsrc,
                                        uint32_t port_mask) {
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
  uint16_t port_id;
  uint8_t count, all_ports_up, print_flag = 0;
  struct rte_eth_link link;
  int ret;
  char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

  printf("\nChecking link status...");
  fflush(stdout);
  for (count = 0; count <= MAX_CHECK_TIME; count++) {
    if (rsrc->force_quit) return;
    all_ports_up = 1;
    RTE_ETH_FOREACH_DEV(port_id) {
      if (rsrc->force_quit) return;
      if ((port_mask & (1 << port_id)) == 0) continue;
      memset(&link, 0, sizeof(link));
      ret = rte_eth_link_get_nowait(port_id, &link);
      if (ret < 0) {
        all_ports_up = 0;
        if (print_flag == 1)
          printf("Port %u link get failed: %s\n", port_id, rte_strerror(-ret));
        continue;
      }
      /* print link status if flag set */
      if (print_flag == 1) {
        rte_eth_link_to_str(link_status_text, sizeof(link_status_text), &link);
        printf("Port %d %s\n", port_id, link_status_text);
        continue;
      }
      /* clear all_ports_up flag if any link down */
      if (link.link_status == RTE_ETH_LINK_DOWN) {
        all_ports_up = 0;
        break;
      }
    }
    /* after finally printing all link status, get out */
    if (print_flag == 1) break;

    if (all_ports_up == 0) {
      printf(".");
      fflush(stdout);
      rte_delay_ms(CHECK_INTERVAL);
    }

    /* set the print_flag if all ports up or timeout */
    if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
      print_flag = 1;
      printf("done\n");
    }
  }
}

static void signal_handler(int signum) {
  struct resolvi_resources *rsrc = resolvi_get_rsrc();
  if (signum == SIGINT || signum == SIGTERM) {
    printf("\n\nSignal %d received, preparing to exit...\n", signum);
    rsrc->force_quit = true;
  }
}

int main(int argc, char **argv) {
  struct resolvi_resources *rsrc;
  uint16_t nb_ports_available = 0;
  uint32_t nb_ports_in_mask = 0;
  uint16_t port_id, last_port;
  uint32_t nb_mbufs;
  int i, ret;

  /* Init EAL. 8< */
  ret = rte_eal_init(argc, argv);
  if (ret < 0) rte_panic("Invalid EAL arguments\n");
  argc -= ret;
  argv += ret;

  rsrc = resolvi_get_rsrc();

  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  /* parse application arguments (after the EAL ones) */
  ret = resolvi_parse_args(argc, argv, rsrc);
  if (ret < 0) rte_panic("Invalid Resolvi arguments\n");
  /* >8 End of init EAL. */

  printf("MAC updating %s\n", rsrc->mac_updating ? "enabled" : "disabled");

  rsrc->nb_phys_ports = rte_eth_dev_count_avail();
  if (rsrc->nb_phys_ports == 0) rte_panic("No Ethernet ports - bye\n");

  /* check port mask to possible port mask */
  if (rsrc->enabled_port_mask & ~((1 << rsrc->nb_phys_ports) - 1))
    rte_panic("Invalid portmask; possible (0x%x)\n",
              (1 << rsrc->nb_phys_ports) - 1);

  /* Create virtio-user ports */
  rsrc->nb_virt_ports = resolvi_create_virtio_user_ports(rsrc);

  /* Create the mbuf pool. 8< */
  nb_mbufs = RTE_MAX(
      rsrc->nb_phys_ports * (RX_DESC_DEFAULT + TX_DESC_DEFAULT + MAX_PKT_BURST +
                             rte_lcore_count() * MEMPOOL_CACHE_SIZE),
      8192U);

  rsrc->pktmbuf_pool =
      rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs, MEMPOOL_CACHE_SIZE, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

  if (rsrc->pktmbuf_pool == NULL) rte_panic("Cannot init mbuf pool\n");
  /* >8 End of create the mbuf pool. */

  /* Create DNS resources. 8< */
  // TODO: Possible per-port pool
  setup_cache(rsrc, rte_socket_id());
  setup_hash(rsrc, rte_socket_id());
  setup_label(rsrc, rte_socket_id());
  /* >8 End of create DNS resources. */

  if (rsrc->evt_vec.enabled) {
    unsigned int nb_vec, vec_size;

    vec_size = rsrc->evt_vec.size;
    nb_vec = (nb_mbufs + vec_size - 1) / vec_size;
    nb_vec = RTE_MAX(512U, nb_vec);
    nb_vec += rte_lcore_count() * 32;
    rsrc->evt_vec_pool = rte_event_vector_pool_create(
        "vector_pool", nb_vec, 32, vec_size, rte_socket_id());
    if (rsrc->evt_vec_pool == NULL)
      rte_panic("Cannot init event vector pool\n");
  }

  nb_ports_available = resolvi_event_init_ports(rsrc);
  if (!nb_ports_available) rte_panic("All available ports are disabled.");

  /* Configure eventdev parameters if required */
  if (rsrc->event_mode)
    resolvi_event_resource_setup(rsrc);
  else
    rte_panic("Poll mode not supported yet\n");

  /* initialize port stats */
  memset(&rsrc->port_stats, 0, sizeof(struct resolvi_port_statistics));

  /* All settings are done. Now enable eth devices */
  RTE_ETH_FOREACH_DEV(port_id) {
    /* skip ports that are not enabled */
    if (!rsrc->port_info[port_id].is_virt &&
        ((rsrc->enabled_port_mask & (1 << port_id)) == 0))
      continue;

    ret = rte_eth_dev_start(port_id);
    if (ret < 0) rte_panic("rte_eth_dev_start:err=%d, port=%u\n", ret, port_id);
  }

  if (rsrc->event_mode) resolvi_event_service_setup(rsrc);

  check_all_ports_link_status(rsrc, rsrc->enabled_port_mask);

  /* launch per-core init on every lcore */
  rte_eal_mp_remote_launch(resolvi_launch_one_lcore, rsrc, SKIP_MAIN);
  resolvi_event_print_stats(rsrc);

  if (rsrc->event_mode) {
    struct resolvi_event_resources *evt_rsrc = rsrc->evt_rsrc;
    for (i = 0; i < evt_rsrc->tx_adptr.nb_tx_adptr; i++)
      rte_event_eth_rx_adapter_stop(evt_rsrc->rx_adptr.rx_adptr[i]);
    for (i = 0; i < evt_rsrc->tx_adptr.nb_tx_adptr; i++)
      rte_event_eth_tx_adapter_stop(evt_rsrc->tx_adptr.tx_adptr[i]);

    RTE_ETH_FOREACH_DEV(port_id) {
      if ((rsrc->enabled_port_mask & (1 << port_id)) == 0) continue;
      ret = rte_eth_dev_stop(port_id);
      if (ret < 0) printf("rte_eth_dev_stop: err=%d, port=%u\n", ret, port_id);
    }

    rte_eal_mp_wait_lcore();
    RTE_ETH_FOREACH_DEV(port_id) {
      if ((rsrc->enabled_port_mask & (1 << port_id)) == 0) continue;
      ret = rte_eth_dev_close(port_id);
    }

    rte_event_dev_stop(evt_rsrc->event_d_id);
    rte_event_dev_close(evt_rsrc->event_d_id);
  } else {
    rte_eal_mp_wait_lcore();

    RTE_ETH_FOREACH_DEV(port_id) {
      if ((rsrc->enabled_port_mask & (1 << port_id)) == 0) continue;
      printf("Closing port %d...", port_id);
      ret = rte_eth_dev_stop(port_id);
      if (ret < 0) printf("rte_eth_dev_stop:err=%d, port=%u\n", ret, port_id);
      rte_eth_dev_close(port_id);
      printf(" Done\n");
    }
  }

  /* clean up the EAL */
  rte_eal_cleanup();
  printf("Bye...\n");

  return ret;
}
