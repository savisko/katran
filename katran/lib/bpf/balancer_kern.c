/*
 * Copyright 2004-present Facebook. All Rights Reserved.
 * This is main balancer's application code
 */

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define bpf_debug(fmt, ...) \
({ \
char ____fmt[] = fmt; \
bpf_trace_printk(____fmt, sizeof(____fmt), \
##__VA_ARGS__); \
})


#include "balancer_consts.h"
#include "balancer_structs.h"
#include "balancer_maps.h"
#include "bpf.h"
#include "bpf_helpers.h"
#include "jhash.h"
#include "pckt_encap.h"
#include "pckt_parsing.h"
#include "handle_icmp.h"


#define SAMPLE_SIZE 64ul
#define MAX_CPUS 128

__attribute__((__always_inline__))
static inline __u32 get_packet_hash(struct packet_description *pckt,
                                    bool hash_16bytes) {
  if (hash_16bytes) {
    return jhash_2words(jhash(pckt->flow.srcv6, 16, INIT_JHASH_SEED_V6),
                        pckt->flow.ports, INIT_JHASH_SEED);
  } else {
    return jhash_2words(pckt->flow.src, pckt->flow.ports, INIT_JHASH_SEED);
  }
}

__attribute__((__always_inline__))
static inline bool is_under_flood(__u64 *cur_time) {
  __u32 conn_rate_key = MAX_VIPS + NEW_CONN_RATE_CNTR;
  struct lb_stats *conn_rate_stats = bpf_map_lookup_elem(
    &stats, &conn_rate_key);
  if (!conn_rate_stats) {
    return true;
  }
  *cur_time = bpf_ktime_get_ns();
  // we are going to check that new connections rate is less than predefined
  // value; conn_rate_stats.v1 contains number of new connections for the last
  // second, v2 - when last time quanta started.
  if ((*cur_time - conn_rate_stats->v2) > ONE_SEC) {
    // new time quanta; reseting counters
    conn_rate_stats->v1 = 1;
    conn_rate_stats->v2 = *cur_time;
  } else {
    conn_rate_stats->v1 += 1;
    if (conn_rate_stats->v1 > MAX_CONN_RATE) {
      // we are exceding max connections rate. bypasing lru update and
      // source routing lookup
      return true;
    }
  }
  return false;
}

__attribute__((__noinline__))
static bool get_packet_dst(struct xdp_md *ctx,
                           struct real_definition **real,
                                  struct packet_description *pckt,
                                  struct vip_meta *vip_info,
                                  bool is_ipv6,
                                  void *lru_map) {

  // to update lru w/ new connection
  struct real_pos_lru new_dst_lru = {};
  bool under_flood = false;
  bool src_found = false;
  __u32 *real_pos;
  __u64 cur_time;
  __u32 hash;
  __u32 key;

  under_flood = is_under_flood(&cur_time);

  #ifdef LPM_SRC_LOOKUP
  if ((vip_info->flags & F_SRC_ROUTING) && !(pckt->flags & F_INLINE_DECAP) &&
      !under_flood) {
    __u32 *lpm_val;
    if (is_ipv6) {
      struct v6_lpm_key lpm_key_v6 = {};
      lpm_key_v6.prefixlen = 128;
      memcpy(lpm_key_v6.addr, pckt->flow.srcv6, 16);
      lpm_val = bpf_map_lookup_elem(&lpm_src_v6, &lpm_key_v6);
    } else {
      struct v4_lpm_key lpm_key_v4 = {};
      lpm_key_v4.addr = pckt->flow.src;
      lpm_key_v4.prefixlen = 32;
      lpm_val = bpf_map_lookup_elem(&lpm_src_v4, &lpm_key_v4);
    }
    if (lpm_val) {
      src_found = true;
      key = *lpm_val;
    }
    __u32 stats_key = MAX_VIPS + LPM_SRC_CNTRS;
    struct lb_stats *data_stats = bpf_map_lookup_elem(&stats, &stats_key);
    if (data_stats) {
      if (src_found) {
        data_stats->v2 += 1;
      } else {
        data_stats->v1 += 1;
      }
    }
  }
  #endif
  if (!src_found) {
    bool hash_16bytes = is_ipv6;

    if (vip_info->flags & F_HASH_DPORT_ONLY) {
      // service which only use dst port for hash calculation
      // e.g. if packets has same dst port -> they will go to the same real.
      // usually VoIP related services.
      pckt->flow.port16[0] = pckt->flow.port16[1];
      memset(pckt->flow.srcv6, 0, 16);
    }
    hash = get_packet_hash(pckt, hash_16bytes) % RING_SIZE;
    key = RING_SIZE * (vip_info->vip_num) + hash;

    bpf_debug("vip_num=%u\n", vip_info->vip_num);
    bpf_debug("RING_SIZE=%u, key=%u\n", RING_SIZE, key);

    real_pos = bpf_map_lookup_elem(&ch_rings, &key);
    if(!real_pos) {
        bpf_debug("real_pos - not found\n");
      return false;
    }
    key = *real_pos;
    bpf_debug("real key=%u\n", key);
  }
  else {
      bpf_debug("src_found\n");
  }
  pckt->real_index = key;
  *real = bpf_map_lookup_elem(&reals, &key);
  if (!(*real)) {
      bpf_debug("real server not found\n");
    return false;
  }
  if (!(vip_info->flags & F_LRU_BYPASS) && !under_flood) {
    if (pckt->flow.proto == IPPROTO_UDP) {
      new_dst_lru.atime = cur_time;
    }
    new_dst_lru.pos = key;
    bpf_debug("calling bpf_map_update_elem()\n");
    bpf_map_update_elem(lru_map, &pckt->flow, &new_dst_lru, BPF_ANY);
  }
  return true;
}

__attribute__((__always_inline__))
static inline void connection_table_lookup(struct real_definition **real,
                                           struct packet_description *pckt,
                                           void *lru_map) {

  struct real_pos_lru *dst_lru;
  __u64 cur_time;
  __u32 key;
  dst_lru = bpf_map_lookup_elem(lru_map, &pckt->flow);
  if (!dst_lru) {
    return;
  }
  if (pckt->flow.proto == IPPROTO_UDP) {
    cur_time = bpf_ktime_get_ns();
    if (cur_time - dst_lru->atime > LRU_UDP_TIMEOUT) {
      return;
    }
    dst_lru->atime = cur_time;
  }
  key = dst_lru->pos;
  pckt->real_index = key;
  *real = bpf_map_lookup_elem(&reals, &key);
  return;
}

__attribute__((__always_inline__))
static inline int process_l3_headers(struct packet_description *pckt,
                                     __u8 *protocol, __u64 off,
                                     __u16 *pkt_bytes, void *data,
                                     void *data_end, bool is_ipv6) {
  __u64 iph_len;
  int action;
  struct iphdr *iph;
  struct ipv6hdr *ip6h;
  if (is_ipv6) {
    ip6h = data + off;
    if (ip6h + 1 > data_end) {
      return XDP_DROP;
    }

    iph_len = sizeof(struct ipv6hdr);
    *protocol = ip6h->nexthdr;
    pckt->flow.proto = *protocol;
    *pkt_bytes = bpf_ntohs(ip6h->payload_len);
    off += iph_len;
    if (*protocol == IPPROTO_FRAGMENT) {
      // we drop fragmented packets
      return XDP_DROP;
    } else if (*protocol == IPPROTO_ICMPV6) {
      action = parse_icmpv6(data, data_end, off, pckt);
      if (action >= 0) {
        return action;
      }
    } else {
      memcpy(pckt->flow.srcv6, ip6h->saddr.s6_addr32, 16);
      memcpy(pckt->flow.dstv6, ip6h->daddr.s6_addr32, 16);
    }
  } else {
    iph = data + off;
    if (iph + 1 > data_end) {
      return XDP_DROP;
    }
    //ihl contains len of ipv4 header in 32bit words
    if (iph->ihl != 5) {
      // if len of ipv4 hdr is not equal to 20bytes that means that header
      // contains ip options, and we dont support em
      return XDP_DROP;
    }

    *protocol = iph->protocol;
    pckt->flow.proto = *protocol;
    *pkt_bytes = bpf_ntohs(iph->tot_len);
    off += IPV4_HDR_LEN_NO_OPT;

    if (iph->frag_off & PCKT_FRAGMENTED) {
      // we drop fragmented packets.
      return XDP_DROP;
    }
    if (*protocol == IPPROTO_ICMP) {
      action = parse_icmp(data, data_end, off, pckt);
      if (action >= 0) {
        return action;
      }
    } else {
      pckt->flow.src = iph->saddr;
      pckt->flow.dst = iph->daddr;
    }
  }
  return FURTHER_PROCESSING;
}

__attribute__((__always_inline__))
static inline int process_encaped_pckt(void **data, void **data_end,
                                       struct xdp_md *xdp, bool *is_ipv6,
                                       struct packet_description *pckt,
                                       __u8 *protocol, __u64 off,
                                       __u16 *pkt_bytes) {
  int action;
  if (*protocol == IPPROTO_IPIP) {
    if (*is_ipv6) {
      if ((*data + sizeof(struct ipv6hdr) +
           sizeof(struct eth_hdr)) > *data_end) {
        return XDP_DROP;
      }
      if (!decap_v6(xdp, data, data_end, true)) {
        return XDP_DROP;
      }
      *is_ipv6 = false;
    } else {
      if ((*data + sizeof(struct iphdr) +
           sizeof(struct eth_hdr)) > *data_end) {
        return XDP_DROP;
      }
      if (!decap_v4(xdp, data, data_end)) {
        return XDP_DROP;
      }
    }
    off = sizeof(struct eth_hdr);
    if (*data + off > *data_end) {
      return XDP_DROP;
    }
    action = process_l3_headers(
      pckt, protocol, off, pkt_bytes, *data, *data_end, false);
    if (action >= 0) {
      return action;
    }
    *protocol = pckt->flow.proto;
  } else if (*protocol == IPPROTO_IPV6) {
    if ((*data + sizeof(struct ipv6hdr) +
         sizeof(struct eth_hdr)) > *data_end) {
      return XDP_DROP;
    }
    if (!decap_v6(xdp, data, data_end, false)) {
      return XDP_DROP;
    }
    off = sizeof(struct eth_hdr);
    if (*data + off > *data_end) {
      return XDP_DROP;
    }
    action = process_l3_headers(
      pckt, protocol, off, pkt_bytes, *data, *data_end, true);
    if (action >= 0) {
      return action;
    }
    *protocol = pckt->flow.proto;
  }
  return FURTHER_PROCESSING;
}

static inline __attribute__((__always_inline__))
__u32 allocate_hw_mark_id(__u32 cpu_num)
{
    (void)cpu_num;
    return 10;
}

static inline __attribute__((__always_inline__))
void deallocate_hw_mark_id(__u32 cpu_num, __u32 mark_id)
{
    (void)cpu_num;
    (void)mark_id;
}

struct xdp_md_mark {
    __u32 mark;
} __attribute__((aligned(4)));

__attribute__((__always_inline__))
static inline int process_packet(struct xdp_md *ctx, void *data, __u64 off, void *data_end,
                                 bool is_ipv6, struct xdp_md *xdp) {

  struct ctl_value *cval = NULL;
  struct real_definition *dst = NULL;
  struct packet_description pckt = {};
  struct vip_definition vip = {};
  struct vip_meta *vip_info = NULL;
  struct lb_stats *data_stats = NULL;
  __u64 iph_len;
  __u8 protocol;
  int hw_accel_supported = 0, lru_map_updated = 0, bypass_vip_lookup = 0;

  int action;
  __u32 vip_num;
  __u32 mac_addr_pos = 0;
  __u16 pkt_bytes;
  size_t data_len;

  struct xdp_md_mark *mark_ptr = (struct xdp_md_mark *)(uintptr_t)xdp->data_meta;
  if (mark_ptr + 1 <= data) {
      __u32 cpu_num, mark_id;
      void *hw_accel_map;

      cpu_num = bpf_get_smp_processor_id();
      hw_accel_map = bpf_map_lookup_elem(&hw_accel_mapping, &cpu_num);
      if (hw_accel_map) {
          hw_accel_supported = 1;
          mark_id = mark_ptr->mark;
          if (mark_id != 0) {
              struct hw_accel_flow *hw_flow;
              //bpf_debug("Received marked packet - mark_id %u\n", mark_id);
              hw_flow = bpf_map_lookup_elem(hw_accel_map, &mark_id);
              if (hw_flow) {
                  vip_num = hw_flow->vip_num;
                  pckt.real_index = hw_flow->real_key;
                  pckt.flow = hw_flow->flow;
                  pckt.flags = 0;
                  vip_info = bpf_map_lookup_elem(&vip_map_by_id, &vip_num);
                  if (vip_info) {
                      __u32 key = pckt.real_index;
                      dst = bpf_map_lookup_elem(&reals, &key);
                      if (dst) {
                          pkt_bytes = (__u16) ((__u64)(data_end - data) - off);
                          bypass_vip_lookup = 1;
                      }
                      else {
                          bpf_debug("Real not found for real_index %u\n", key);
                      }
                  }
                  else {
                      bpf_debug("VIP not found for vip_num %u\n", vip_num);
                  }
              }
              else {
                  bpf_debug("hw_flow not found for mark_id %u\n", mark_id);
              }
          }
          else {
              bpf_debug("Received NOT marked packet\n");
          }
      }
      else {
          bpf_debug("HW acceleration map not found for CPU %u\n", cpu_num);
      }
  }

  if (!bypass_vip_lookup) {
      action = process_l3_headers(
        &pckt, &protocol, off, &pkt_bytes, data, data_end, is_ipv6);
      if (action >= 0) {
        return action;
      }
      protocol = pckt.flow.proto;

      #ifdef INLINE_DECAP
      if (protocol == IPPROTO_IPIP || protocol == IPPROTO_IPV6) {
        struct address dst_addr = {};
        if (is_ipv6) {
          memcpy(dst_addr.addrv6, pckt.flow.dstv6, 16);
        } else {
          dst_addr.addr = pckt.flow.dst;
        }
        __u32 *decap_dst_flags = bpf_map_lookup_elem(&decap_dst, &dst_addr);

        action = process_encaped_pckt(&data, &data_end, xdp, &is_ipv6, &pckt,
                                      &protocol, off, &pkt_bytes);
        if (action >= 0) {
          return action;
        }

        if (decap_dst_flags) {
          __u32 stats_key = MAX_VIPS + REMOTE_ENCAP_CNTRS;
          data_stats = bpf_map_lookup_elem(&stats, &stats_key);
          if (!data_stats) {
            return XDP_DROP;
          }
          data_stats->v1 += 1;
          pckt.flags |= F_INLINE_DECAP;
        } else {
          // it's ipip encapsulated packet but not to decap dst. so just pass
          // decapsulated packet to the kernel
          return XDP_PASS;
        }
      }
      #endif

      if (protocol == IPPROTO_TCP) {
        if (!parse_tcp(data, data_end, is_ipv6, &pckt)) {
          return XDP_DROP;
        }
      } else if (protocol == IPPROTO_UDP) {
        if (!parse_udp(data, data_end, is_ipv6, &pckt)) {
          return XDP_DROP;
        }
      } else {
        // send to tcp/ip stack
        return XDP_PASS;
      }

      if (is_ipv6) {
        memcpy(vip.vipv6, pckt.flow.dstv6, 16);
      } else {
        vip.vip = pckt.flow.dst;
      }

      vip.port = pckt.flow.port16[1];
      vip.proto = pckt.flow.proto;
      vip_info = bpf_map_lookup_elem(&vip_map, &vip);
      if (!vip_info) {
        vip.port = 0;
        vip_info = bpf_map_lookup_elem(&vip_map, &vip);
        if (!vip_info) {
          //bpf_debug("VIP not found - XDP_PASS\n");
          return XDP_PASS;
        }

        if (!(vip_info->flags & F_HASH_DPORT_ONLY)) {
          // VIP, which doesnt care about dst port (all packets to this VIP w/ diff
          // dst port but from the same src port/ip must go to the same real
          pckt.flow.port16[1] = 0;
        }
      }
      //bpf_debug("\n");
      bpf_debug("VIP found\n");
  }

  data_len = data_end - data;

  if (data_len > MAX_PCKT_SIZE) {
#ifdef ICMP_TOOBIG_GENERATION
    __u32 stats_key = MAX_VIPS + ICMP_TOOBIG_CNTRS;
    data_stats = bpf_map_lookup_elem(&stats, &stats_key);
    if (!data_stats) {
      return XDP_DROP;
    }
    if (is_ipv6) {
      data_stats->v2 += 1;
    } else {
      data_stats->v1 += 1;
    }
    return send_icmp_too_big(xdp, is_ipv6, data_end - data);
#else
    //bpf_debug("data length %lu is bigger than MAX_PCKT_SIZE=%d - XDP_DROP\n", data_len, MAX_PCKT_SIZE);
    return XDP_DROP;
#endif
  }

  if (!data_stats) {
      __u32 stats_key = MAX_VIPS + LRU_CNTRS;
      data_stats = bpf_map_lookup_elem(&stats, &stats_key);
      if (!data_stats) {
          //bpf_debug("No stats - XDP_DROP\n");
        return XDP_DROP;
      }
  }

  // totall packets
  data_stats->v1 += 1;

  if ((vip_info->flags & F_QUIC_VIP)) {
    int real_index;
    real_index = parse_quic(data, data_end, is_ipv6, &pckt);
    if (real_index > 0) {
      __u32 key = real_index;
      __u32 *real_pos = bpf_map_lookup_elem(&quic_mapping, &key);
      if (real_pos) {
        key = *real_pos;
        pckt.real_index = key;
        dst = bpf_map_lookup_elem(&reals, &key);
        if (!dst) {
            //bpf_debug("F_QUIC_VIP - XDP_DROP\n");
          return XDP_DROP;
        }
      }
    }
  }

  if (!dst) {
    if ((vip_info->flags & F_HASH_NO_SRC_PORT)) {
      // service, where diff src port, but same ip must go to the same real,
      // e.g. gfs
      pckt.flow.port16[0] = 0;
    }
    __u32 cpu_num = bpf_get_smp_processor_id();
    void *lru_map = bpf_map_lookup_elem(&lru_maps_mapping, &cpu_num);
    if (!lru_map) {
        //bpf_debug("lru_map NOT found for cpu_num=%u\n", cpu_num);
      lru_map = &fallback_lru_cache;
      __u32 lru_stats_key = MAX_VIPS + FALLBACK_LRU_CNTR;
      struct lb_stats *lru_stats = bpf_map_lookup_elem(&stats, &lru_stats_key);
      if (!lru_stats) {
          //bpf_debug("No lru_stats - XDP_DROP\n");
        return XDP_DROP;
      }
      // we weren't able to retrieve per cpu/core lru and falling back to
      // default one. this counter should never be anything except 0 in prod.
      // we are going to use it for monitoring.
      lru_stats->v1 += 1;
    }

    if (!(pckt.flags & F_SYN_SET) &&
        !(vip_info->flags & F_LRU_BYPASS)) {
      connection_table_lookup(&dst, &pckt, lru_map);
      if (dst) {
          bpf_debug("lru_map match\n", cpu_num);
      }
      else {
          bpf_debug("lru_map miss\n", cpu_num);
      }
    }
    else {
        if (pckt.flags & F_SYN_SET)
        {
            bpf_debug("F_SYN_SET\n", cpu_num);
        }
        if (vip_info->flags & F_LRU_BYPASS)
        {
            bpf_debug("F_LRU_BYPASS\n", cpu_num);
        }
    }
    if (!dst) {
      if (pckt.flow.proto == IPPROTO_TCP) {
        __u32 lru_stats_key = MAX_VIPS + LRU_MISS_CNTR;
        struct lb_stats *lru_stats = bpf_map_lookup_elem(
          &stats, &lru_stats_key);
        if (!lru_stats) {
            //bpf_debug("No lru_stats - XDP_DROP\n");
          return XDP_DROP;
        }
        if (pckt.flags & F_SYN_SET) {
          // miss because of new tcp session
          lru_stats->v1 += 1;
        } else {
          // miss of non-syn tcp packet. could be either because of LRU trashing
          // or because another katran is restarting and all the sessions
          // have been reshuffled
          lru_stats->v2 += 1;
        }
      }
      if(!get_packet_dst(ctx, &dst, &pckt, vip_info, is_ipv6, lru_map)) {
          //bpf_debug("Destination not found - XDP_DROP\n");
        return XDP_DROP;
      }
      // lru misses (either new connection or lru is full and starts to trash)
      data_stats->v2 += 1;

      lru_map_updated = 1;
    }
  }

  bpf_debug("Destination found: flags=%x, dst=%x\n", (__u32) dst->flags, dst->dst);

  cval = bpf_map_lookup_elem(&ctl_array, &mac_addr_pos);

  if (!cval) {
      //bpf_debug("Default MAC not found - XDP_DROP\n");
    return XDP_DROP;
  }

  if (dst->flags & F_IPV6) {
    if(!encap_v6(xdp, cval, is_ipv6, &pckt, dst, pkt_bytes)) {
      return XDP_DROP;
    }
  } else {
    if(!encap_v4(xdp, cval, &pckt, dst, pkt_bytes)) {
        //bpf_debug("encap_v4 failed - XDP_DROP\n");
      return XDP_DROP;
    }
  }
  vip_num = vip_info->vip_num;
  data_stats = bpf_map_lookup_elem(&stats, &vip_num);
  if (!data_stats) {
      //bpf_debug("No data_stats for VIP - XDP_DROP\n");
    return XDP_DROP;
  }
  data_stats->v1 += 1;
  data_stats->v2 += pkt_bytes;

  // per real statistics
  data_stats = bpf_map_lookup_elem(&reals_stats, &pckt.real_index);
  if (!data_stats) {
      //bpf_debug("No data_stats for real - XDP_DROP\n");
    return XDP_DROP;
  }
  data_stats->v1 += 1;
  data_stats->v2 += pkt_bytes;

  if (/*hw_accel_supported &&*/ lru_map_updated) {
      bpf_debug("lru_map_updated=1\n");
      if (!is_ipv6 && !(vip_info->flags & F_LRU_BYPASS) && !(vip_info->flags & F_QUIC_VIP) && !(pckt.flags & F_INLINE_DECAP)) {
          __u32 cpu_num, mark_id;
          void *hw_accel_map;
          int ret;

          cpu_num = bpf_get_smp_processor_id();
          hw_accel_map = bpf_map_lookup_elem(&hw_accel_mapping, &cpu_num);
          if (!hw_accel_map) {
              bpf_debug("HW acceleration map not found for CPU %u\n", cpu_num);
          }
          else {
              mark_id = allocate_hw_mark_id(cpu_num);
              if (!mark_id) {
                  bpf_debug("Failed to allocate mark_id\n");
              }
              else {
                  struct hw_accel_flow hw_flow;

                  //bpf_debug("allocated mark_id %u\n", mark_id);

                  hw_flow.vip_num = vip_num;
                  hw_flow.real_key = pckt.real_index;
                  hw_flow.flow = pckt.flow;

                  //bpf_debug("calling bpf_map_update_elem for mark_id=%u, vip_num=%u, real_key=%u\n",
                  //          mark_id, hw_flow.vip_num, hw_flow.real_key);
                  if ((ret = bpf_map_update_elem(hw_accel_map, &mark_id, &hw_flow, BPF_ANY)) != 0) {
                      bpf_debug("bpf_map_update_elem() failed: %d\n", ret);
                      deallocate_hw_mark_id(cpu_num, mark_id);
                  }
                  else
                  {
                      /* Metadata will be in the perf event before the packet data. */
                      struct hw_accel_event metadata;
                      __u64 flags;
                      __u16 sample_size;

                      /* The XDP perf_event_output handler will use the upper 32 bits
                       * of the flags argument as a number of bytes to include of the
                       * packet payload in the event data. If the size is too big, the
                       * call to bpf_perf_event_output will fail and return -EFAULT.
                       *
                       * See bpf_xdp_event_output in net/core/filter.c.
                       *
                       * The BPF_F_CURRENT_CPU flag means that the event output fd
                       * will be indexed by the CPU number in the event map.
                       */
                      flags = BPF_F_CURRENT_CPU;
                      sample_size = 16;

                      metadata.real_ip = dst->dst;
                      metadata.mark_id = mark_id;
                      metadata.rx_queue_index = ctx->rx_queue_index;
                      metadata.flow = pckt.flow;

                      flags |= (__u64)sample_size << 32;

                      bpf_debug("calling bpf_perf_event_output()\n");
                      ret = bpf_perf_event_output(ctx, &hw_accel_events, flags, &metadata, sizeof(metadata));
                      if (ret)
                          bpf_debug("bpf_perf_event_output() failed: %d\n", ret);
                  }
              }
          }
      }
  }

  bpf_debug("XDP_TX\n\n");
  return XDP_TX;
}

SEC("xdp-balancer")
int balancer_ingress(struct xdp_md *ctx) {
  void *data = (void *) (uintptr_t)ctx->data;
  void *data_end = (void *)(uintptr_t)ctx->data_end;
  struct eth_hdr *eth = data;
  __u32 eth_proto;
  __u32 nh_off;
  bool is_ipv6;
  nh_off = sizeof(struct eth_hdr);

  //bpf_debug("Inside balancer_ingress: line %d\n", __LINE__);

  if (data + nh_off > data_end) {
    // bogus packet, len less than minimum ethernet frame size
    return XDP_DROP;
  }

  eth_proto = eth->eth_proto;

  if (eth_proto == BE_ETH_P_IP) {
      is_ipv6 = false;
    //return process_packet(ctx, data, nh_off, data_end, false, ctx);
  } else if (eth_proto == BE_ETH_P_IPV6) {
      is_ipv6 = true;
    //return process_packet(ctx, data, nh_off, data_end, true, ctx);
  } else {
    // pass to tcp/ip stack
    return XDP_PASS;
  }
  return process_packet(ctx, data, nh_off, data_end, is_ipv6, ctx);
}

char _license[] SEC("license") = "GPL";
