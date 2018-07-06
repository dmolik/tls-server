%{
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>

#include "server.h"
#include "config_file.h"

config_t *p_config;

int  yylex(void);
void yyerror(char *str, ...);
int  yyval;
int  yyparse();

%}


%union
{
	double  d;
	char   *string;
	int     i;
}

%token <d> DECIMAL;
%token <i> INT;
%token <string> STRING;
%token <string> LOG_FACILITY;
%token <string> LOG_TYPE;
%token <string> LOG_LEVEL;

%token PIDFILE;
%token USER;
%token GROUP;
%token WORKERS;
%token LOG;
%token LOGLEVEL;
%token LOGTYPE;
%token FACILITY;
%token PORT;

%%

configuration:
	| configuration config
	| configuration LOG optional_eol '{' log_section '}'
	;

config:
	  PIDFILE STRING { p_config->pid     = $2; }
	| USER    STRING { p_config->uid     = $2; }
	| GROUP   STRING { p_config->gid     = $2; }
	| WORKERS INT    { p_config->workers = $2; }
	| PORT    INT    { p_config->port    = $2; }
	;

log_section:
	| log_section log_statement
	;

log_statement:
	  LOGLEVEL LOG_LEVEL    { p_config->log.level    = $2; }
	| LOGTYPE  LOG_TYPE     { p_config->log.type     = $2; }
	| FACILITY LOG_FACILITY { p_config->log.facility = $2; }
	;

optional_eol:
	| optional_eol '\n'
	;

%%


void yyerror(char *str, ...)
{
	fprintf(stderr, "error: %s\n", str);
	extern int yylineno;
	fprintf (stderr, "configuration file line: %d\n", yylineno);
}

int yywrap()
{
	return 1;
}

int parse_config_file (config_t *config_ref, const char *path)
{
	// parse the configuration file and store the results in the structure referenced
	// error messages are output to stderr
	// Returns: 0 for success, otherwise non-zero if an error occurred
	//
	extern FILE *yyin;
	extern int yylineno;

	p_config = malloc(sizeof(config_t));
	p_config = config_ref;

	yyin = fopen (path, "r");
	if (yyin == NULL) {
		fprintf (stderr, "can't open configuration file %s: %s\n", path, strerror(errno));
		return -1;
	}

	yylineno = 1;
	if (yyparse ()) {
		fclose (yyin);
		return -1;
	} else
		return 0;
}
