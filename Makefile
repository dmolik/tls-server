CFLAGS  := -Wall -Wextra -pipe -pedantic -std=gnu99
LIBS    := -lcrypto -lssl -lpthread
PERF    ?=
ifeq ($(PERF), 1)
LDFLAGS := -Wl,--as-needed -Wl,--hash-style=gnu
CFLAGS  += -O3 -march=native -mtune=native -flto=8
endif

BIN = server

all: $(BIN)

$(BIN): src/$(BIN).o src/main.o src/daemon.o src/log.o src/parse.o src/scanner.o
	$(CC) $(CFLAGS) $(LIBS) $(LDFLAGS) -o $@ $^
ifeq ($(PERF), 1)
	strip $(BIN)
endif

src/parse.c: src/parse.y
	$(YACC) -d --output-file=$@ $<

src/scanner.c: src/scanner.l
	$(LEX) --header-file --yylineno --outfile=$@ $<

src/%.o: src/%.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<


exp: pairs
pairs:
	$(CC) $(CFLAGS) $(LIBS) $(LDFLAGS) -o $@ exp/$@.c

clean:
	rm -f src/*.o src/scanner.c src/parse.c src/parse.h $(BIN) pairs
