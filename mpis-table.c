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

void add_entry(uint8_t target_type, const char *ifname, uint32_t selector, uint32_t target, uint8_t cidr, uint32_t target_data, uint8_t flags) {
    mpis_table *current_entry = &table[n_entries++];
    memset(current_entry, 0, sizeof(mpis_table));

    current_entry->iif = if_nametoindex(ifname);
    if (current_entry->iif == 0) {
        log_error("invalid interface name '%s': %s\n", ifname, strerror(errno));
        retval = -1;
        return;
    }

    if ((cidr > 32 || cidr < 16) && !(flags & TFLAG_OVERRIDE_FRAG)) {
        log_error("invalid prefix length - must be between 16 and 32 if not using override-frag\n");
        retval = -1;
        return;
    }

    current_entry->selector = selector;
    current_entry->cidr = cidr;
    current_entry->mask = ~((1 << (32 - cidr)) - 1);
    current_entry->target_type = target_type;
    current_entry->target = target;
    current_entry->target_data = target_data;
    current_entry->target_flags = flags;
}

void store_retval(int val) {
    retval = val;
}

int get_retval() {
    return retval;
}