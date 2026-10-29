# Builds only the C bridge; the OpenConnect client, the netstack sidecar and the
# helper files in lib/ are produced by the Dockerfile before acap-build runs this.

PROG = OpenConnect_VPN
SRCS = main.c
PKGS = axparameter glib-2.0 gio-2.0

# -std=gnu11 keeps the GCC 13 C23 stdlib redirect off, so strtol() and friends
# bind GLIBC_2.17 symbols rather than __isoc23_* @ GLIBC_2.38 (absent below OS 12.10).
CFLAGS += -Wall -Wextra -Werror -O2 -std=gnu11 $(shell pkg-config --cflags $(PKGS))
LDFLAGS += -Wl,-z,noexecstack
LDLIBS += $(shell pkg-config --libs $(PKGS))

STRIP ?= strip

all: $(PROG)
	$(STRIP) $(PROG)

$(PROG): $(SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f $(PROG)
