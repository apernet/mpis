#ifndef MPIS_TABLE_H
#define MPIS_TABLE_H

typedef struct _mpis_table {

} mpis_table;

void new_table();
void end_table();
mpis_table *get_table();

void store_retval(int retval);
int get_retval();

int parse_routes(const char *filename, mpis_table **table);

#endif // MPIS_TABLE_H