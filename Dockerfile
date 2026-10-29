# OpenConnect VPN ACAP: a libopenconnect-based GlobalProtect client + userspace netstack.
#
#   docker build --build-arg ARCH=aarch64 --target package -t openconnect_vpn-aarch64 .
#   docker build --build-arg ARCH=armv7hf --target package -t openconnect_vpn-armv7hf .
#
# Prefer ./build.sh, which does both and collects the .eap files in ./releases.
#
# zlib, OpenSSL and libxml2 are cross-compiled as static libraries so the
# OpenConnect binary only depends on glibc: the sysroot's shared copies carry
# sonames and symbol versions that older AXIS OS releases do not have.
ARG ARCH=aarch64
ARG SDK_VERSION=12.10.0
ARG UBUNTU_VERSION=24.04
ARG SDK_REPO=docker.io/axisecp
ARG SDK=acap-native-sdk

# ── Go build stage: the userspace netstack + proxy sidecar ─────────────────
FROM docker.io/golang:1.27.3 AS gobuilder
ARG ARCH
ENV CGO_ENABLED=0
COPY app/netstack /src/netstack
WORKDIR /src/netstack
RUN case "$ARCH" in \
        aarch64) export GOARCH=arm64 ;; \
        armv7hf) export GOARCH=arm GOARM=7 ;; \
        *) echo "unsupported ARCH $ARCH" >&2; exit 1 ;; \
    esac && \
    go build -trimpath -ldflags='-s -w' -o /netstack_proxy . && \
    ls -l /netstack_proxy

# ── OpenConnect and its static dependencies ────────────────────────────────
FROM ${SDK_REPO}/${SDK}:${SDK_VERSION}-${ARCH}-ubuntu${UBUNTU_VERSION} AS openconnect
ARG ARCH

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
        ca-certificates curl xz-utils perl make pkg-config && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

ARG OPENCONNECT_VERSION=9.21
ARG OPENCONNECT_SHA256=5b32369467db6e5f317aa1ed12cfcbb81ed00bdbc765450b6bfcbdc300944a58
# renovate: datasource=github-releases depName=madler/zlib extractVersion=^v(?<version>.+)$
ARG ZLIB_VERSION=1.3.2
ARG ZLIB_SHA256=bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16
# OpenSSL 3.5 is the current LTS line.
# renovate: datasource=github-releases depName=openssl/openssl extractVersion=^openssl-(?<version>.+)$
ARG OPENSSL_VERSION=3.5.9
ARG OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
# renovate: datasource=gitlab-tags registryUrl=https://gitlab.gnome.org depName=GNOME/libxml2 extractVersion=^v(?<version>.+)$
ARG LIBXML2_VERSION=2.15.4
ARG LIBXML2_SHA256=98087fd181d9070724f3fbc65c7377db03038eb92bd882374daff44940138821

# Every library is compiled with -std=gnu11, which keeps GCC 13's C23 stdlib
# redirect (strtol -> __isoc23_strtol @ GLIBC_2.38, absent below AXIS OS 12.10)
# off for code that does not define _GNU_SOURCE; the isoc23 shim below covers
# the code that does.
ENV DEPS=/opt/deps
# Parallel compiles under emulation can exhaust a small Podman/Docker VM.
ARG MAKE_JOBS=3
WORKDIR /src

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN curl -fsSL -o zlib.tar.gz \
        "https://github.com/madler/zlib/releases/download/v${ZLIB_VERSION}/zlib-${ZLIB_VERSION}.tar.gz" && \
    echo "${ZLIB_SHA256}  zlib.tar.gz" | sha256sum -c - && \
    tar xzf zlib.tar.gz && \
    . /opt/axis/acapsdk/environment-setup* && \
    cd "zlib-${ZLIB_VERSION}" && \
    CFLAGS="$CFLAGS -std=gnu11 -fPIC" ./configure --static --prefix="$DEPS" && \
    make -j"$MAKE_JOBS" libz.a && make install

RUN curl -fsSL -o openssl.tar.gz \
        "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" && \
    echo "${OPENSSL_SHA256}  openssl.tar.gz" | sha256sum -c - && \
    tar xzf openssl.tar.gz && \
    . /opt/axis/acapsdk/environment-setup* && \
    unset CROSS_COMPILE && \
    CC_BIN=$(echo "$CC" | awk '{print $1}') && \
    CC_ARGS=$(echo "$CC" | cut -s -d' ' -f2-) && \
    case "$($CC_BIN -dumpmachine)" in \
        aarch64*) OSSL_TARGET=linux-aarch64 ;; \
        arm*)     OSSL_TARGET=linux-armv4 ;; \
        *) echo "unknown OpenSSL target: $($CC_BIN -dumpmachine)" >&2; exit 1 ;; \
    esac && \
    cd "openssl-${OPENSSL_VERSION}" && \
    ./Configure "$OSSL_TARGET" no-shared no-module no-dso no-tests no-docs no-apps \
        --prefix="$DEPS" --libdir=lib --openssldir=/etc/ssl \
        CC="$CC_BIN" CFLAGS="$CC_ARGS $CFLAGS -std=gnu11" AR="$AR" RANLIB="$RANLIB" && \
    make -j"$MAKE_JOBS" build_libs && make install_dev

RUN curl -fsSL -o libxml2.tar.xz \
        "https://download.gnome.org/sources/libxml2/${LIBXML2_VERSION%.*}/libxml2-${LIBXML2_VERSION}.tar.xz" && \
    echo "${LIBXML2_SHA256}  libxml2.tar.xz" | sha256sum -c - && \
    tar xJf libxml2.tar.xz && \
    . /opt/axis/acapsdk/environment-setup* && \
    cd "libxml2-${LIBXML2_VERSION}" && \
    CFLAGS="$CFLAGS -std=gnu11" ./configure $CONFIGURE_FLAGS --prefix="$DEPS" \
        --enable-static --disable-shared --without-python --without-zlib --without-lzma \
        --without-icu --without-readline --without-history --without-modules --without-debug && \
    make -j"$MAKE_JOBS" && make install

# Only our static deps are visible to pkg-config (never the sysroot's shared
# copies). The *_LIBS overrides name the archives outright: the SDK's $CC
# carries -L<sysroot>/usr/lib, which would otherwise win over $DEPS/lib and pull
# in e.g. libxml2.so. The isoc23 shim is linked last; see native/isoc23_compat.c.
COPY native/isoc23_compat.c /src/isoc23_compat.c
RUN curl -fsSL -o openconnect.tar.gz \
        "https://www.infradead.org/openconnect/download/openconnect-${OPENCONNECT_VERSION}.tar.gz" && \
    echo "${OPENCONNECT_SHA256}  openconnect.tar.gz" | sha256sum -c - && \
    tar xzf openconnect.tar.gz && \
    . /opt/axis/acapsdk/environment-setup* && \
    $CC $CFLAGS -std=gnu11 -c /src/isoc23_compat.c -o /src/isoc23_compat.o && \
    "$AR" rcs "$DEPS/lib/libisoc23compat.a" /src/isoc23_compat.o && \
    cd "openconnect-${OPENCONNECT_VERSION}" && \
    export PKG_CONFIG="pkg-config --static" PKG_CONFIG_PATH= PKG_CONFIG_SYSROOT_DIR= \
           PKG_CONFIG_LIBDIR="$DEPS/lib/pkgconfig" \
           OPENSSL_CFLAGS="-I$DEPS/include" \
           OPENSSL_LIBS="$DEPS/lib/libssl.a $DEPS/lib/libcrypto.a -lpthread -ldl" \
           LIBXML2_CFLAGS="-I$DEPS/include/libxml2" LIBXML2_LIBS="$DEPS/lib/libxml2.a -lm -lpthread" \
           ZLIB_CFLAGS="-I$DEPS/include" ZLIB_LIBS="$DEPS/lib/libz.a" \
           LIBS="$DEPS/lib/libz.a $DEPS/lib/libisoc23compat.a -lm" \
           LDFLAGS="$LDFLAGS -Wl,--wrap=fmod" && \
    CFLAGS="$CFLAGS -std=gnu11" ./configure $CONFIGURE_FLAGS --prefix=/opt/openconnect \
        --disable-shared --enable-static --without-gnutls \
        --with-vpnc-script=/bin/true --without-external-browser \
        --disable-nls --disable-docs --without-libproxy --without-stoken \
        --without-libpcsclite --without-libpskc --without-gssapi --without-java \
        --disable-vhost-net && \
    make -j"$MAKE_JOBS" libopenconnect.la && \
    mkdir -p /opt/out && \
    cp COPYING.LGPL /opt/out/

# The GlobalProtect client (app/client) links libopenconnect statically; kept
# in its own step so client changes do not rebuild OpenConnect.
COPY app/client/gp_client.c /src/client/gp_client.c
RUN . /opt/axis/acapsdk/environment-setup* && \
    OC="/src/openconnect-${OPENCONNECT_VERSION}" && \
    $CC $CFLAGS -std=gnu11 -Wall -Wextra -Werror -I"$OC" -c /src/client/gp_client.c -o /src/client/gp_client.o && \
    $CC $CFLAGS $LDFLAGS -Wl,--wrap=fmod -o /opt/out/gp-client /src/client/gp_client.o \
        "$OC/.libs/libopenconnect.a" "$DEPS/lib/libxml2.a" "$DEPS/lib/libssl.a" "$DEPS/lib/libcrypto.a" \
        "$DEPS/lib/libz.a" "$DEPS/lib/libisoc23compat.a" -lm -ldl -lpthread && \
    "$STRIP" /opt/out/gp-client && \
    ls -l /opt/out

# Fail the build rather than ship a binary the oldest supported AXIS OS cannot load.
RUN . /opt/axis/acapsdk/environment-setup* && \
    "$OBJDUMP" -p /opt/out/gp-client | grep NEEDED && \
    newest=$("$OBJDUMP" -T /opt/out/gp-client | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' | sort -uV | tail -1) && \
    echo "newest glibc symbol version: $newest" && \
    if [ "$(printf '2.37\n%s\n' "$newest" | sort -V | tail -1)" != "2.37" ]; then \
        echo "gp-client needs GLIBC_$newest, newer than AXIS OS below 12.10 provides" >&2; exit 1; \
    fi && \
    if "$OBJDUMP" -p /opt/out/gp-client | grep NEEDED | grep -qE 'libssl|libcrypto|libxml2|libz\.'; then \
        echo "gp-client links a shared copy of a dependency that must be static" >&2; exit 1; \
    fi

# ── package the ACAP ───────────────────────────────────────────────────────
FROM openconnect AS package
ARG ARCH
COPY app /opt/app/
COPY LICENSE /opt/app/LICENSE
COPY --from=gobuilder /netstack_proxy /opt/app/lib/netstack_proxy
WORKDIR /opt/app
# The CA bundle is a fallback for devices without a system bundle; OpenConnect
# prefers the camera's own when one exists.
RUN cp /opt/out/gp-client lib/gp-client && \
    cp /opt/out/COPYING.LGPL lib/COPYING.LGPL && \
    cp /etc/ssl/certs/ca-certificates.crt lib/ca-bundle.crt && \
    chmod 755 lib/gp-client lib/netstack_proxy lib/tun-script.sh && \
    chmod 644 lib/COPYING.LGPL lib/ca-bundle.crt && \
    sed -i "s/\"BUILDARCH\"/\"${ARCH}\"/" manifest.json && \
    find . -name .DS_Store -delete && \
    rm -rf netstack client && \
    . /opt/axis/acapsdk/environment-setup* && acap-build ./

FROM scratch
COPY --from=package /opt/app/*.eap /
