#ifndef __RESOLVI_VERDICT_H__
#define __RESOLVI_VERDICT_H__

#include "resolvi_common.h"
#include "resolvi_cache.h"

static __rte_always_inline int resolvi_l3_verdict(
    struct resolvi_resources *rsrc, struct rte_mbuf *mbuf,
    struct resolvi_pkt_info *info) {
  struct rte_ipv4_hdr *ipv4_hdr = info->ipv4_hdr;
  struct rte_ipv6_hdr *ipv6_hdr = info->ipv6_hdr;
  uint32_t pkt_type, l3_type, is_udp;
  int verdict = PKT_PASS;

  printf("pkt_type: %x -> ", mbuf->packet_type);
  pkt_type = RTE_PTYPE_L3_MASK | RTE_PTYPE_L4_UDP;
  pkt_type &= mbuf->packet_type;
  is_udp = pkt_type & RTE_PTYPE_L4_UDP;

  rte_prefetch0(rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *) + 1);

  info->l3_off = sizeof(struct rte_ether_hdr);

  if (!is_udp) return verdict;

  if (RTE_ETH_IS_IPV4_HDR(pkt_type)) {
    ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *,
                                       sizeof(struct rte_ether_hdr));

    info->l4_off = info->l3_off + ipv4_hdr->ihl * 4;
    verdict = CONTINUE;
    printf("l3 type: IPv4 -> ");
  }
  if (RTE_ETH_IS_IPV6_HDR(pkt_type)) {
    ipv6_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv6_hdr *,
                                       sizeof(struct rte_ether_hdr));

    // Not processing additional headers.
    if (ipv6_hdr->proto != IPPROTO_UDP) return PKT_PASS;
    info->l4_off = info->l3_off + sizeof(struct rte_ipv6_hdr);
    verdict = CONTINUE;
    printf("l3 type: %IPv6 -> ");
  }

  fflush(stdout);

  return verdict;
}

static __rte_always_inline int resolvi_l4_verdict(
    struct resolvi_resources *rsrc, struct rte_mbuf *mbuf,
    struct resolvi_pkt_info *info, bool is_qry) {
  struct rte_udp_hdr *udp_hdr = info->udp_hdr;

  udp_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, info->l4_off);

  printf("l4 port: %d -> ", rte_be_to_cpu_16(udp_hdr->dst_port));
  fflush(stdout);

  if (is_qry)
    if (udp_hdr->dst_port != RTE_BE16(53))
      return PKT_PASS;
    else if (udp_hdr->src_port != RTE_BE16(53))
      return PKT_PASS;
  info->l7_off = info->l4_off + sizeof(struct rte_udp_hdr);

  return CONTINUE;
}

static __rte_always_inline uint16_t
resolvi_read_label(struct resolvi_resources *rsrc, struct rte_mbuf *mbuf,
                   struct resolvi_pkt_info *info, char *label) {
  uint8_t len = 0, cpy_len = 0;

  len = *rte_pktmbuf_mtod_offset(mbuf, uint8_t *, info->cur_off);
  info->cur_off += sizeof(uint8_t);
  if (len > 0) {
    cpy_len = RTE_MIN(len, DNS_MAX_LABEL_LEN);
    rte_memcpy(label, rte_pktmbuf_mtod_offset(mbuf, char *, info->cur_off),
               cpy_len);
    label[cpy_len] = '\0';
    info->cur_off += len;
  }
  return len;
}

#define DNS_QRY_FLAGS_MASK 0xFF01
#define DNS_RSP_FLAGS_MASK 0xFF8F

static __rte_always_inline int resolvi_l7_verdict(
    struct resolvi_resources *rsrc, struct rte_mbuf *mbuf,
    struct resolvi_pkt_info *info, bool is_qry, char **dns_name) {
  struct resolvi_dns_hdr *dns_hdr;
  void *buf = NULL;
  char *label, *name;
  uint16_t label_len = 0, name_len = 0;
  // TODO: Temporary
  char domain[] = "bilibili";
  int verdict = PKT_PASS;

  if (rte_mempool_get(rsrc->dns_label_pool, &buf) < 0) {
    // TODO: While this should NEVER happen, in prod we should handle this.
    rte_panic("Failed to allocate memory for DNS label\n");
  }

  memset(buf, 0, DNS_MAX_LABEL_LEN + DNS_MAX_QUERY_NAME);

  // Divide the requested buffer into label and name buffers.
  name = (char *)buf;
  label = (char *)(buf + DNS_MAX_QUERY_NAME);

  *dns_name = name;

  dns_hdr =
      rte_pktmbuf_mtod_offset(mbuf, struct resolvi_dns_hdr *, info->l7_off);
  printf("l7 flags: %04x -> ", dns_hdr->flags);
  fflush(stdout);
  // Test for supported DNS header flags
  if (is_qry) {
    if ((dns_hdr->flags | DNS_QRY_FLAGS_MASK) != DNS_QRY_FLAGS_MASK)
      return PKT_PASS;
  } else {
    if ((dns_hdr->flags | DNS_RSP_FLAGS_MASK) != DNS_RSP_FLAGS_MASK)
      return PKT_PASS;
  }
  info->cur_off = info->l7_off + sizeof(struct resolvi_dns_hdr);

  do {
    memset(label, 0, DNS_MAX_LABEL_LEN);
    label_len = resolvi_read_label(rsrc, mbuf, info, label);
    if (label_len == 0) {
      name[name_len - 1] = '\0';
      break;
    }
    if (name_len + label_len > DNS_MAX_QUERY_NAME - 1) break;
    if (strncmp(label, domain, label_len) != 0) verdict = CONTINUE;
    rte_memcpy(name + name_len, label, label_len);  // Copy label to name
    name_len += label_len;
    name[name_len] = '.';
    name_len++;
  } while (!rsrc->force_quit);

  printf("Name Len: %d, Name: %s, verdict: %d\n", name_len, name, verdict);
  fflush(stdout);

  // Postponde the put action
  // rte_mempool_put(rsrc->dns_label_pool, buf);

  return verdict;
}

static __rte_always_inline int resolvi_reverse_pkt(
    struct resolvi_resources *rsrc, struct rte_mbuf *mbuf,
    struct resolvi_pkt_info *info, struct dns_cache_item *cache) {
  struct rte_ipv4_hdr *ipv4_hdr = info->ipv4_hdr;
  struct rte_ipv6_hdr *ipv6_hdr = info->ipv6_hdr;
  struct rte_udp_hdr *udp_hdr = info->udp_hdr;
  uint16_t len;
  rte_be32_t ipv4_addr;
  uint8_t ipv6_addr[16];
  rte_be16_t port;
  char *append_loc;
  int ret;

  /* Trim off the DNS query */
  len = rte_be_to_cpu_16(udp_hdr->dgram_len);
  ret = rte_pktmbuf_trim(mbuf, len - sizeof(struct rte_udp_hdr));
  if (ret) {
    printf("Failed to trim packet\n");
    return PKT_PASS;
  }

  /* Append DNS response */
  len = strlen(cache->full_packet);
  append_loc = rte_pktmbuf_append(mbuf, len);
  if (append_loc) {
    printf("Failed to append packet\n");
    return PKT_PASS;
  }

  /* Copy full dns response to the start */
  rte_memcpy((void *)append_loc, cache->full_packet, len);

  /* Change UDP len */
  len += sizeof(struct rte_udp_hdr);
  udp_hdr->dgram_len = rte_cpu_to_be_16(len);
  /* Swap UDP ports */
  port = udp_hdr->src_port;
  udp_hdr->src_port = udp_hdr->dst_port;
  udp_hdr->dst_port = port;

  if (RTE_ETH_IS_IPV4_HDR(mbuf->packet_type)) {
    ipv4_hdr->total_length =
        rte_cpu_to_be_16(len + sizeof(struct rte_ipv4_hdr));
    ipv4_addr = ipv4_hdr->dst_addr;
    ipv4_hdr->dst_addr = ipv4_hdr->src_addr;
    ipv4_hdr->src_addr = ipv4_addr;
    ipv4_hdr->hdr_checksum = 0;
    if ((mbuf->ol_flags & RTE_MBUF_F_TX_IP_CKSUM) == 0)
      ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
  } else if (RTE_ETH_IS_IPV6_HDR(mbuf->packet_type)) {
    ipv6_hdr->payload_len = rte_cpu_to_be_16(len);
    rte_memcpy(ipv6_addr, ipv6_hdr->dst_addr, 16);
    rte_memcpy(ipv6_hdr->dst_addr, ipv6_hdr->src_addr, 16);
    rte_memcpy(ipv6_hdr->src_addr, ipv6_addr, 16);
  }

  udp_hdr->dgram_cksum = 0;
  if ((mbuf->ol_flags & RTE_MBUF_F_TX_UDP_CKSUM) == 0) {
    if (RTE_ETH_IS_IPV4_HDR(mbuf->packet_type))
      rte_ipv4_udptcp_cksum_mbuf(mbuf, ipv4_hdr, info->l4_off);
    else if (RTE_ETH_IS_IPV6_HDR(mbuf->packet_type))
      rte_ipv6_udptcp_cksum_mbuf(mbuf, ipv6_hdr, info->l4_off);
  }
}

#endif /* __RESOLVI_VERDICT_H__ */