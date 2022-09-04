%{
    #include <stdint.h>
    #include <arpa/inet.h>
    #include <string.h>
    #include <errno.h>
    #include "mpis-table.h"
    #include "log.h"

    extern int yylineno;
    extern int yylex();
    extern FILE *yyin;

    static const char *_filename;

    void yyerror(const char *s);

    #define ERR_IF_NULL(x) if ((x) == NULL) { \
        store_retval(-1);\
        log_error("internal error while parsing mpis routing table.\n");\
        YYERROR;\
    }
%}

%locations
%define parse.error verbose

%union {
    uint32_t u32;
    char *str;
}

%token <str> IDENT
%token <u32> IP NUMBER
%token SRC DST IIF
%token ENCAP DECAP SWAP CUTOFF_TTL
%token SLASH

%%
mips_table
    : mips_table mips_entry
    | mips_entry

mips_entry
    : IIF IDENT SRC IP SLASH NUMBER ENCAP IP CUTOFF_TTL NUMBER {
        add_entry($2, $4, $6, TTYPE_ENCAP, $8, 0, $10);
        free($2);
    }
    | IIF IDENT DST IP SWAP IP CUTOFF_TTL NUMBER {
        add_entry($2, $4, 0, TTYPE_SWAP, $6, 0, $8);
        free($2);
    }
    | IIF IDENT DST IP DECAP IP SLASH NUMBER {
        add_entry($2, $4, 0, TTYPE_DECAP, $6, $8, 0);
        free($2);
    }

%%

int parse_routes(const char *filename, mpis_table **table) {
    _filename = filename;

    FILE *f = fopen(filename, "r");
    if (!f) {
        log_fatal("failed to open config file %s", filename);
        return -1;
    }

    new_table();

    yyin = f;
    yyparse();
    fclose(f);

    end_table();

    *table = get_table();

    return get_retval();
}

void yyerror(const char *s) {
    log_fatal("%s:%d - %s\n", _filename, yylineno, s);
    store_retval(-1);
}