#ifndef MPIS_TABLE_H
#define MPIS_TABLE_H
#include <stdint.h>

#define TTYPE_ENCAP 1
#define TTYPE_DECAP 2
#define TTYPE_SWAP 3

typedef struct _mpis_table {
    uint32_t iif;
    uint32_t selector;
    uint32_t target;

    uint16_t selector_mask_last16; // valid if selector_type == STYPE_FROM
    uint16_t target_mask_last16; // valid if target_type == TTYPE_DECAP

    uint8_t selector_cidr; // valid if selector_type == STYPE_FROM
    uint8_t target_cidr; // valid if target_type is TTYPE_DECAP

    // for now, only valid when target_type = TTYPE_SWAP. data is cutoff-ttl value.
    uint8_t target_data;

    uint8_t target_type;

    struct _mpis_table *next;
} mpis_table;

void new_table();
void end_table();
mpis_table *get_table();

void add_entry(const char *ifname, uint32_t selector, uint8_t selector_cidr, uint8_t target_type, uint32_t target, uint8_t target_cidr, uint32_t target_data);

void store_retval(int retval);
int get_retval();

int parse_routes(const char *filename, mpis_table **table);

#endif // MPIS_TABLE_H