


static struct {
	FILE *console;
	char *ident;
	int   level;
} LIBVIGOR_LOG = {
	.console = NULL,
	.ident   = NULL,
	.level   = LOG_INFO
};

void log_open(const char *ident, const char *facility);
void log_close(void);
void logger(int level, const char *fmt, ...);
int log_level_number(const char *name);
