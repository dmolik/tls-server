CFLAGS  := -Wall -Wextra -pipe -pedantic -std=c99 -g
LIBS    := -lcrypto -lssl -lpthread
PERF    ?=
ifeq ($(PERF), 1)
LDFLAGS := -Wl,--as-needed -Wl,--hash-style=gnu
CFLAGS  += -O3 -march=native -mtune=native -flto=8
endif

OBJS += src/daemon.o src/log.o src/utils.o

BINS  = server client gen_cert

server_OBJS   := src/server.o $(OBJS) src/parse.o src/scanner.o src/main.o
client_OBJS   := src/client.o $(OBJS)
gen_cert_OBJS := src/gen_cert.o

all: $(BINS)

define PROGRAM_template =
 $(1): $$($(1)_OBJS) $$($(1)_LIBS:%=-l%)
 ALL_OBJS   += $$($(1)_OBJS)
endef

$(foreach prog,$(BINS),$(eval $(call PROGRAM_template,$(prog))))

$(BINS):
	$(CC) $(CFLAGS) $(LIBS) $(LDFLAGS) -o $@ ${$@_OBJS}
ifeq ($(PERF), 1)
	strip $@
endif

src/scanner.c: src/scanner.l src/parse.c
	$(LEX) --header-file --yylineno --outfile=$@ $<
src/parse.c: src/parse.y
	$(YACC) -d --output-file=src/parse.c $<
src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<
scan: clean
	scan-build -v make all

TESTS :=
TESTS += 01-mem

testdata: $(BINS) t/data/server.conf

t/data/server.conf:
	$(shell t/rig)

test: check
check: testdata
	prove -v $(addprefix ./t/,$(TESTS))

clean:
	rm -f  src/*.o src/scanner.c src/parse.c src/parse.h ${BINS}
	rm -rf t/data
