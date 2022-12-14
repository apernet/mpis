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
    uint8_t u8;
    char *str;
}

%token <str> IDENT
%token <u32> IP NUMBER
%token SRC DST IIF
%token ENCAP DECAP SWAP CUTOFF_TTL
%token SLASH
%token BYPASS_LINUX OVERRIDE_FRAG

%type <u8> entry_flags entry_flag

%%
mpis_table
    : mpis_table mpis_entry
    | mpis_entry

mpis_entry
    : IIF IDENT SRC IP SLASH NUMBER ENCAP IP CUTOFF_TTL NUMBER entry_flags {
        add_entry(TTYPE_ENCAP, $2, $4, $8, $6, $10, $11);
        free($2);
    }
    | IIF IDENT DST IP SWAP IP CUTOFF_TTL NUMBER entry_flags {
        add_entry(TTYPE_SWAP, $2, $4, $6, 0, $8, $9);
        free($2);
    }
    | IIF IDENT DST IP DECAP IP SLASH NUMBER entry_flags {
        add_entry(TTYPE_DECAP, $2, $4, $6, $8, 0, $9);
        free($2);
    }

entry_flags
    : entry_flags entry_flag {
        $$ = $1 | $2;
    }
    | entry_flag

entry_flag
    : %empty {
        $$ = 0;
    }
    | BYPASS_LINUX {
        $$ = TFLAG_BYPASS_LINUX;
    }
    | OVERRIDE_FRAG {
        $$ = TFLAG_OVERRIDE_FRAG;
    }

%%

ssize_t parse_routes(const char *filename, mpis_table **table) {
    size_t sz = 0;
    _filename = filename;
    

    FILE *f = fopen(filename, "r");
    if (!f) {
        log_fatal("failed to open config file %s\n", filename);
        return -1;
    }

    new_table();

    yyin = f;
    yyparse();
    fclose(f);

    end_table();

    *table = get_table(&sz);

    if (get_retval() < 0) {
        return -1;
    }

    return sz;
}

void yyerror(const char *s) {
    log_fatal("%s:%d - %s\n", _filename, yylineno, s);
    store_retval(-1);
}