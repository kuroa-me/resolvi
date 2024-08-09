#include "resolvi_cache.h"

struct rte_hash *resolvi_cache_lookup_struct[NB_SOCKETS];
struct dns_cache_item *resolvi_cache[NB_SOCKETS][CACHE_MAX];

void setup_cache(struct resolvi_resources *rsrc, const int socketid) {
  char pool_name[RTE_MEMPOOL_NAMESIZE];
  uint32_t nb_elem, elt_size;
  int ret;

  /* Create the DNS cache pool. 8< */
  snprintf(pool_name, sizeof(pool_name), "resolvi_dns_cache_%d",
           rte_lcore_id());

  /* systemd-resolved default */
  nb_elem = CACHE_MAX - 1;
  elt_size = DNS_PACKET_UNICAST_SIZE_MAX;

  rsrc->dns_cache_pool = rte_mempool_create_empty(pool_name, nb_elem, elt_size,
                                                  0, 0, rte_socket_id(), 0);
  if (rsrc->dns_cache_pool == NULL)
    rte_panic("Cannot init DNS cache pool, %d KiB hugepages requested",
              nb_elem * elt_size / 1024);

  if (rte_mempool_set_ops_byname(rsrc->dns_cache_pool,
                                 rte_mbuf_best_mempool_ops(), NULL))
    rte_panic("Error setting dns_cache_pool handler\n");

  ret = rte_mempool_populate_default(rsrc->dns_cache_pool);
  if (ret != nb_elem)
    rte_panic("Intended to populate %d, got %d\n", nb_elem, ret);
  /* >8 End of create the DNS cache pool. */
}

void setup_hash(struct resolvi_resources *rsrc, const int socketid) {
  struct rte_hash_parameters resolvi_cache_hash_params = {
      .name = NULL,
      .entries = CACHE_MAX,
      .key_len = sizeof(union dns_query_name),
      .hash_func = hash_dns_name_crc,
      .hash_func_init_val = 0,
      .extra_flag = RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD |
                    RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT |
                    RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
  };

  char s[64];

  /* create hash */
  snprintf(s, sizeof(s), "resolvi_dns_query_hash_%d", socketid);
  resolvi_cache_hash_params.name = s;
  resolvi_cache_hash_params.socket_id = socketid;
  resolvi_cache_lookup_struct[socketid] =
      rte_hash_create(&resolvi_cache_hash_params);
  if (resolvi_cache_lookup_struct[socketid] == NULL)
    rte_panic("Unable to create resolvi cache hash on socket %d=n", socketid);

  // TODO: Pre-feed hash table from config file?
}

void setup_label(struct resolvi_resources *rsrc, const int socketid) {
  char pool_name[RTE_MEMPOOL_NAMESIZE];
  uint32_t nb_elem, elt_size;
  int ret;

  nb_elem = rsrc->nb_phys_ports * rte_lcore_count();
  elt_size = DNS_MAX_LABEL_LEN + DNS_MAX_QUERY_NAME;

  snprintf(pool_name, sizeof(pool_name), "resolvi_label_pool_%d",
           rte_lcore_id());
  rsrc->dns_label_pool = rte_mempool_create_empty(
      pool_name, nb_elem, elt_size, 0,
      1 /* 1 event process use only 1 element*/, socketid, 0);
  if (rsrc->dns_label_pool == NULL)
    rte_panic("Err: %s, %d B hugepages requested", rte_strerror(rte_errno),
              nb_elem * elt_size);

  if (rte_mempool_set_ops_byname(rsrc->dns_label_pool,
                                 rte_mbuf_best_mempool_ops(), NULL))
    rte_panic("Error setting dns_label_pool handler\n");

  ret = rte_mempool_populate_default(rsrc->dns_label_pool);
  if (ret != nb_elem)
    rte_panic("Intended to populate %d, got %d\n", nb_elem, ret);
}

struct rte_hash *get_resolvi_cache_lookup_struct(const int socket_id) {
  return resolvi_cache_lookup_struct[socket_id];
}

struct dns_cache_item *get_resolvi_cache(const int socket_id,
                                         const int cache_id) {
  return resolvi_cache[socket_id][cache_id];
}

void *del_resolvi_cache(const int socket_id, const int cache_id) {
  resolvi_cache[socket_id][cache_id] = NULL;
}

void *set_resolvi_cache(const int socket_id, const int cache_id,
                        struct dns_cache_item *item) {
  resolvi_cache[socket_id][cache_id] = item;
}