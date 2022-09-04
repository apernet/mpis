#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
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

SEC("xdp") int mpis(struct xdp_md *ctx) {
    // todo

    return XDP_PASS;
}