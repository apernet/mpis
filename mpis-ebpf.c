#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
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

static __always_inline int do_encap(struct iphdr *ip, mpis_table *entry) {
    if (entry->target_data >= ip->ttl) {
        ip->daddr = entry->target;
        goto encap_send;
    }

    ip->id = (((__u16 *) (&ip->saddr))[1] & ~entry->mask_last16) | (ip->id & entry->mask_last16);
    ip->saddr = ip->daddr;
    ip->daddr = entry->target;

encap_send:
    cksum(ip);
    return XDP_PASS;
}

static __always_inline int do_decap_or_swap(struct iphdr *ip, mpis_table *entry) {
    if (entry->target_type == TTYPE_DECAP) {
        ip->daddr = ip->saddr;
        ip->saddr = entry->target | ((ip->id & ~entry->mask_last16) << 16);
    } else if (entry->target_type == TTYPE_SWAP) {
        if (entry->target_data >= ip->ttl) {
            return XDP_PASS;
        }

        ip->daddr = entry->target;
    }

    cksum(ip);
    return XDP_PASS;
}

SEC("xdp") int mpis(struct xdp_md *ctx) {
    void *data_end = (void *)(long) ctx->data_end;
    void *data = (void *)(long) ctx->data;
    struct ethhdr *eth = data;
    struct vlan_hdr *vhdr;
    struct iphdr *ip;
    void *l3hdr;
    mpis_table *entry = NULL;
    __u16 ether_proto;
    __u32 lpm_key[2];

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
        return do_encap(ip, entry);
    }

    entry = bpf_map_lookup_elem(&decap_swap_map, &ip->daddr);
    if (entry != NULL && entry->iif == ctx->ingress_ifindex) {
        return do_decap_or_swap(ip, entry);
    }

    return XDP_PASS;
}