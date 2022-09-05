%{
    #include <arpa/inet.h>
    #include "mpis-table.tab.h"
%}

%option noyywrap
%option nounput
%option noinput
%option yylineno

%%
[ \t\n] {}

\#[^\n]* {}

src {
    return SRC;
}

dst {
    return DST;
}

iif {
    return IIF;
}

encap {
    return ENCAP;
}

decap {
    return DECAP;
}

swap {
    return SWAP;
}

cutoff-ttl {
    return CUTOFF_TTL;
}

bypass-linux {
    return BYPASS_LINUX;
}

\/ {
    return SLASH;
}

([0-9]{1,3}\.){3}[0-9]{1,3} {
    inet_pton(AF_INET, yytext, &yylval.u32);
    return IP;
}

[0-9]+ {
    yylval.u32 = atoi(yytext);
    return NUMBER;
}

[a-zA-Z]+[a-zA-Z0-9_\-]* {
    yylval.str = strdup(yytext);
    return IDENT;
}

%%