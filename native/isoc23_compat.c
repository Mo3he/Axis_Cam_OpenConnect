// SPDX-License-Identifier: BSD-3-Clause

/*
 * Keeps lib/openconnect loadable on AXIS OS < 12.10 (glibc 2.34). With glibc
 * 2.38 headers, _GNU_SOURCE (which OpenConnect and parts of OpenSSL define)
 * redirects strtol/strtoul/sscanf and friends to __isoc23_* @ GLIBC_2.38, which
 * older firmware lacks; -std=gnu11 alone does not prevent that. These forwarders
 * satisfy such references with the classic symbols. <stdlib.h>/<stdio.h> are
 * deliberately not included: their redirect would turn these calls back into
 * __isoc23_* and recurse.
 */
#include <stdarg.h>

extern long strtol(const char *nptr, char **endptr, int base);
extern unsigned long strtoul(const char *nptr, char **endptr, int base);
extern long long strtoll(const char *nptr, char **endptr, int base);
extern unsigned long long strtoull(const char *nptr, char **endptr, int base);
extern int vsscanf(const char *str, const char *format, va_list ap);

long __isoc23_strtol(const char *nptr, char **endptr, int base) { return strtol(nptr, endptr, base); }

unsigned long __isoc23_strtoul(const char *nptr, char **endptr, int base) { return strtoul(nptr, endptr, base); }

long long __isoc23_strtoll(const char *nptr, char **endptr, int base) { return strtoll(nptr, endptr, base); }

unsigned long long __isoc23_strtoull(const char *nptr, char **endptr, int base) { return strtoull(nptr, endptr, base); }

int __isoc23_vsscanf(const char *str, const char *format, va_list ap) { return vsscanf(str, format, ap); }

int __isoc23_sscanf(const char *str, const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    int ret = vsscanf(str, format, ap);
    va_end(ap);
    return ret;
}

/*
 * glibc 2.38 also gave fmod a new default version (fmod@GLIBC_2.38, used by
 * libxml2's XPath). The link passes -Wl,--wrap=fmod so every call lands here,
 * and .symver binds this one to the original version every firmware exports.
 */
#if defined(__aarch64__)
#define GLIBC_BASE_VERSION "GLIBC_2.17"
#elif defined(__arm__)
#define GLIBC_BASE_VERSION "GLIBC_2.4"
#else
#error "unsupported architecture"
#endif

extern double fmod_base(double x, double y);
__asm__(".symver fmod_base, fmod@" GLIBC_BASE_VERSION);

double __wrap_fmod(double x, double y) { return fmod_base(x, y); }
