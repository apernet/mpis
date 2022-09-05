#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <sys/socket.h>
#include "mpis.h"
#include "mpis-table.h"

char _license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(key_size, 8);
    __type(value, mpis_table);
    __uint(max_entries, MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} encap_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, mpis_table);
    __uint(max_entries, MAX_ENTRIES);
} decap_swap_map SEC(".maps");

struct vlan_hdr {
    __be16 vlan_id;
    __be16 inner_ether_proto;
};

// todo: incremental checksum?
static __always_inline void cksum(struct iphdr *ip) {
    __u32 sum = 0;
    __u16 *ptr = (__u16 *) ip;
    __u8 i;

    ip->check = 0;

    #pragma clang loop unroll(full)
    for (i = 0; i < (int) sizeof(struct iphdr) / 2; ++i) {
        sum += *ptr++;
    }

    ip->check = ~((sum & 0xffff) + (sum >> 16));
}

static __always_inline void do_encap(struct iphdr *ip, mpis_table *entry) {
    if (entry->target_data >= ip->ttl) {
        ip->daddr = entry->target;
        return cksum(ip);
    }

    ip->id = (((__u16 *) &ip->saddr)[1] & entry->mask_last16) | (ip->id & ~entry->mask_last16);
    ip->saddr = ip->daddr;
    ip->daddr = entry->target;

    cksum(ip);
}

static __always_inline void do_decap_or_swap(struct iphdr *ip, mpis_table *entry) {
    if (entry->target_type == TTYPE_DECAP) {
        ip->daddr = ip->saddr;
        ip->saddr = bpf_htonl(bpf_ntohl(entry->target) | bpf_ntohs((ip->id & entry->mask_last16)));
    } else if (entry->target_type == TTYPE_SWAP) {
        if (entry->target_data >= ip->ttl) {
            return;
        }

        ip->daddr = entry->target;
    }

    cksum(ip);
}

SEC("xdp") int mpis(struct xdp_md *ctx) {
    void *data_end = (void *)(long) ctx->data_end;
    void *data = (void *)(long) ctx->data;
    struct ethhdr *eth = data;
    struct vlan_hdr *vhdr;
    struct iphdr *ip;
    struct bpf_fib_lookup fib_params = {};
    void *l3hdr;
    mpis_table *entry = NULL;
    __u16 ether_proto;
    __u32 lpm_key[2];
    int matched = 0;
    long ret;

    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_DROP;
    }

    l3hdr = data + sizeof(struct ethhdr);
    ether_proto = bpf_ntohs(eth->h_proto);

    // vlan? just skip the header.
    if (ether_proto == ETH_P_8021Q || ether_proto == ETH_P_8021AD) {
        if (l3hdr + sizeof(struct vlan_hdr) > data_end) {
            return XDP_DROP;
        }
        
        vhdr = l3hdr;
        l3hdr += sizeof(struct vlan_hdr);
        ether_proto = vhdr->inner_ether_proto;
    }

    // qinq? just skip again.
    if (ether_proto == ETH_P_8021Q || ether_proto == ETH_P_8021AD) {
        if (l3hdr + sizeof(struct vlan_hdr) > data_end) {
            return XDP_DROP;
        }
        
        vhdr = l3hdr;
        l3hdr += sizeof(struct vlan_hdr);
        ether_proto = vhdr->inner_ether_proto;
    }

    if (ether_proto != ETH_P_IP) {
        return XDP_PASS; // don't care
    }

    if (l3hdr + sizeof(struct iphdr) > data_end) {
        return XDP_DROP;
    }

    ip = l3hdr;

    lpm_key[0] = 32;
    lpm_key[1] = ip->saddr;
    entry = bpf_map_lookup_elem(&encap_map, &lpm_key);
    if (entry != NULL && entry->iif == ctx->ingress_ifindex) {
        do_encap(ip, entry);
        matched = 1;
    }

    if (!matched) {
        entry = bpf_map_lookup_elem(&decap_swap_map, &ip->daddr);
        if (entry != NULL && entry->iif == ctx->ingress_ifindex) {
            matched = 1;
            do_decap_or_swap(ip, entry);
        }
    }

    if (matched && entry->target_flags & TFLAG_BYPASS_LINUX) {
        fib_params.family = AF_INET;
        fib_params.tos = ip->tos;
        fib_params.l4_protocol = ip->protocol;
        fib_params.sport = 0;
        fib_params.dport = 0;
        fib_params.tot_len = bpf_ntohs(ip->tot_len);
        fib_params.ipv4_src = ip->saddr;
        fib_params.ipv4_dst = ip->daddr;
        fib_params.ifindex = ctx->ingress_ifindex;

        ret = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);

        if (ret == BPF_FIB_LKUP_RET_SUCCESS) {
            __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
            __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
            return bpf_redirect(fib_params.ifindex, 0);
        } 
    }

    return XDP_PASS;
}