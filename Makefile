CFLAGS  := -Wall -Wextra -pipe -pedantic -std=c99
LIBS    := -lcrypto -lssl -lurcu -lpthread
PERF    ?=
ifeq ($(PERF), 1)
LDFLAGS := -Wl,--as-needed -Wl,--hash-style=gnu
CFLAGS  += -O3 -march=native -mtune=native -flto=8
endif

BIN = server

all: $(BIN)

$(BIN): $(BIN).o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) $(LDFLAGS)
ifeq ($(PERF), 1)
	strip $(BIN)
endif

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)


clean:
	rm -f *.o $(BIN)
