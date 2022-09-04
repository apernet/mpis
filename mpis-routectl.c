#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <getopt.h>
#include "log.h"
#include "mpis-table.h"

void usage(const char *me) {
    fprintf(stderr, "usage: %s [-adhrs] -t mpis-table-file -e epbf-object [interfaces ...]\n", me);
    fprintf(stderr, "    -a: attach (default)\n");
    fprintf(stderr, "    -d: detach\n");
    fprintf(stderr, "    -r: re-attach\n");
    fprintf(stderr, "    -s: xdp skb mode\n");
    fprintf(stderr, "    -h: help\n");
}

int ebpf_loadprog(const char* progname, struct bpf_object** to, int *fd);
int populate_table(struct bpf_object *obj, const mpis_table *table, int *dfd, int *efd);
int attach(int prog_fd, unsigned int ifindex, int flags);
int detach(unsigned int ifindex, int flags);

int main(int argc, char **argv) {
    int ret, prog_fd, dmap_fd, emap_fd, i, skb_mode = 0, xdp_flags = 0;
    unsigned int ifindex;
    mpis_table *table = NULL;
    struct bpf_object *obj;
    char op = 'a', opt;
    const char *ebpf_name = NULL, *table_file_name = NULL;

    while ((opt = getopt(argc, argv, "gadrst:e:")) != -1) {
        switch (opt) {
            case 'a':
            case 'd':
            case 'r':
                op = opt;
                continue;
            case 'h':
                usage(argv[0]);
                return 0;
            case 't':
                table_file_name = optarg;
                continue;
            case 'e':
                ebpf_name = optarg;
                continue;
            case 's':
                skb_mode = 1;
                continue;
            default:
                usage(argv[0]);
                return 1;
        }
    }

    if (ebpf_name == NULL || table_file_name == NULL) {
        usage(argv[0]);
        return 1;
    }

    ret = parse_routes(table_file_name, &table);

    if (ret < 0) {
        usage(argv[0]);
        return 1;
    }

    ret = ebpf_loadprog(ebpf_name, &obj, &prog_fd);
    if (ret < 0) {
        return 1;
    }

    ret = populate_table(obj, table, &dmap_fd, &emap_fd);
    if (ret < 0) {
        return 1;
    }

    xdp_flags = skb_mode ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE;

    log_debug("loaded mpis table.\n");

    argc -= optind;
    argv += optind;

    for (i = 0; i < argc; i++) {
        ifindex = if_nametoindex(argv[i]);
        if (ifindex == 0) {
            log_error("if_nametoindex(%s): %s\n", argv[i], strerror(errno));
            return 1;
        }

        if (op == 'a') {
            ret = attach(prog_fd, ifindex, xdp_flags);
            if (ret < 0) {
                return 1;
            }
        } else if (op == 'd') {
            ret = detach(ifindex, xdp_flags);
            if (ret < 0) {
                return 1;
            }
        } else if (op == 'r') {
            ret = detach(ifindex, xdp_flags);
            if (ret < 0) {
                return 1;
            }
            ret = attach(prog_fd, ifindex, xdp_flags);
            if (ret < 0) {
                return 1;
            }
        } 
    }

    log_info("mpis loaded and running.\n");

    return 0;
}

int ebpf_loadprog(const char* progname, struct bpf_object** to, int *fd) {
    int ret, prog_fd;
    struct bpf_object *obj;
    struct bpf_program *prog;

    obj = bpf_object__open_file(progname, NULL);
    if (libbpf_get_error(obj)) {
        log_error("failed to open object file '%s'", progname);
        return -1;
    }

    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        log_error("failed to find program in object file '%s'\n", progname);
        return -1;
    }

    bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);

    ret = bpf_object__load(obj);
    if (ret) {
        log_error("failed to load object file '%s': %s", progname, strerror(errno));
        return -1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        log_error("failed to retrieve ebpf program fd.\n");
        return -1;
    }

    *to = obj;
    *fd = prog_fd;

    return 0;
}

int populate_table(struct bpf_object *obj, const mpis_table *table, int *dfd, int *efd) {
    int ret, emap_fd, dmap_fd;
    const mpis_table *tptr;
    struct bpf_lpm_trie_key *key;

    emap_fd = bpf_object__find_map_fd_by_name(obj, "encap_map");
    dmap_fd = bpf_object__find_map_fd_by_name(obj, "decap_swap_map");

    if (emap_fd < 0 || dmap_fd < 0) {
        log_error("failed to retrieve mpis map fd.\n");
        return -1;
    }

    tptr = table;
    key = malloc(sizeof(struct bpf_lpm_trie_key) + 4);

    while (tptr != NULL) {
        if (tptr->selector_type == STYPE_FROM) {
            key->prefixlen = tptr->selector_cidr;
            memcpy(key->data, &tptr->selector, sizeof(uint32_t));

            ret = bpf_map_update_elem(emap_fd, key, tptr, 0);

            if (ret < 0) {
                log_error("failed to update encap map: %s\n", strerror(errno));
                return -1;
            }
        } else if (tptr->target_type == TTYPE_DECAP || tptr->target_type == TTYPE_SWAP) {
            ret = bpf_map_update_elem(dmap_fd, &tptr->selector, tptr, BPF_ANY);

            if (ret < 0) {
                log_error("failed to update decap map: %s\n", strerror(errno));
                return -1;
            }
        }

        tptr = tptr->next;
    }

    *dfd = dmap_fd;
    *efd = emap_fd;

    return 0;
}

int attach(int prog_fd, unsigned int ifindex, int flags) {
    return bpf_xdp_attach(ifindex, prog_fd, flags, NULL);
}

int detach(unsigned int ifindex, int flags) {
    return bpf_xdp_detach(ifindex, flags, NULL);
}