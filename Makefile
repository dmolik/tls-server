CFLAGS  := -Wall -Wextra -pipe -pedantic -std=c99 -g
LIBS    := -lcrypto -lssl -lpthread
PERF    ?=
ifeq ($(PERF), 1)
LDFLAGS := -Wl,--as-needed -Wl,--hash-style=gnu
CFLAGS  += -O3 -march=native -mtune=native -flto=8
endif

SERVER = server
CLIENT = client

OBJS += src/daemon.o src/log.o src/utils.o

SERVER_OBJS = $(OBJS) src/parse.o src/scanner.o src/main.o
CLIENT_OBJS = $(OBJS)

all: $(SERVER) $(CLIENT)

$(SERVER): src/$(SERVER).o $(SERVER_OBJS)
	$(CC) $(CFLAGS) $(LIBS) $(LDFLAGS) -o $@ $^
ifeq ($(PERF), 1)
	strip $(BIN)
endif

$(CLIENT): src/$(CLIENT).o $(CLIENT_OBJS)
	$(CC) $(CFLAGS) $(LIBS) $(LDFLAGS) -o $@ $^
ifeq ($(PERF), 1)
	strip $(BIN)
endif

src/scanner.c: src/scanner.l src/parse.c
	$(LEX) --header-file --yylineno --outfile=$@ $<
src/parse.c: src/parse.y
	$(YACC) -d --output-file=src/parse.c $<
src/%.o: src/%.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

scan: clean
	scan-build -v make all

clean:
	rm -f src/*.o src/scanner.c src/parse.c src/parse.h $(SERVER) $(CLIENT)
