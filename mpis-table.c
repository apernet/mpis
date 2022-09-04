#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>
#include "mpis-table.h"
#include "log.h"
#include "mpis.h"

static mpis_table table[MAX_ENTRIES];
static int retval;
static size_t n_entries;

void new_table() {
    retval = 0;
    n_entries = 0;
}

void end_table() {
    // nothing to do for now
}

mpis_table *get_table(size_t *table_sz) {
    *table_sz = n_entries;
    return table;
}

void add_entry(uint8_t target_type, const char *ifname, uint32_t selector, uint32_t target, uint8_t cidr, uint32_t target_data) {
    mpis_table *current_entry = &table[n_entries++];
    memset(current_entry, 0, sizeof(mpis_table));

    // todo: verify selector_cidr >= 16

    current_entry->iif = if_nametoindex(ifname);
    if (current_entry->iif == 0) {
        log_error("invalid interface name '%s': %s\n", ifname, strerror(errno));
        retval = -1;
        return;
    }

    current_entry->selector = selector;
    current_entry->cidr = cidr;
    current_entry->mask_last16 = ~((1 << (16 - cidr)) - 1);
    current_entry->target_type = target_type;
    current_entry->target = target;
    current_entry->target_data = target_data;
}

void store_retval(int val) {
    retval = val;
}

int get_retval() {
    return retval;
}