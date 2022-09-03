#include <stdio.h>
#include "log.h"
#include "mpis-table.h"

void usage(const char *me) {
    fprintf(stderr, "usage: %s mpis-table-file\n", me);
}

int main(int argc, char **argv) {
    int ret;
    mpis_table *table;

    if (argc != 2) {
        usage(argv[0]);
        return 1;
    }

    ret = parse_routes(argv[1], &table);

    if (ret < 0) {
        usage(argv[0]);
        return 1;
    }

    return 0;
}