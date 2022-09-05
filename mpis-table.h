#ifndef MPIS_TABLE_H
#define MPIS_TABLE_H
#include <stdint.h>
#include <unistd.h>

#define TTYPE_ENCAP         0x01
#define TTYPE_DECAP         0x02
#define TTYPE_SWAP          0x03

#define TFLAG_BYPASS_LINUX  0b00000001
#define TFLAG_OVERRIDE_FRAG 0b00000010

typedef struct _mpis_table {
    uint32_t iif;
    uint32_t selector;
    uint32_t target;

    // mask & cidr: valid if action is not swap
    uint16_t mask_last16;
    uint8_t cidr;

    // valid if type is not decap. data is cutoff-ttl value.
    uint8_t target_data;

    // TTYPE_*
    uint8_t target_type;

    // TFLAG_*
    uint8_t target_flags;
} mpis_table;

void new_table();
void end_table();
mpis_table *get_table();

void add_entry(uint8_t target_type, const char *ifname, uint32_t selector, uint32_t target, uint8_t cidr, uint32_t target_data, uint8_t flags);

void store_retval(int retval);
int get_retval();

ssize_t parse_routes(const char *filename, mpis_table **table);

#endif // MPIS_TABLE_H