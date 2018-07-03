CFLAGS  := -Wall -Wextra -pipe -pedantic -std=c99
LIBS    := -lcrypto -lssl -lpthread
PERF    ?=
ifeq ($(PERF), 1)
LDFLAGS := -Wl,--as-needed -Wl,--hash-style=gnu
CFLAGS  += -O3 -march=native -mtune=native -flto=8
endif

BIN = server

all: $(BIN)

$(BIN): src/$(BIN).o
	$(CC) $(CFLAGS) $(LIBS) $(LDFLAGS) -o $@ $^
ifeq ($(PERF), 1)
	strip $(BIN)
endif

src/%.o: src/%.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

exp: pairs
pairs:
	$(CC) $(CFLAGS) $(LIBS) $(LDFLAGS) -o $@ exp/$@.c

clean:
	rm -f src/*.o $(BIN) pairs
