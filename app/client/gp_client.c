// SPDX-License-Identifier: BSD-3-Clause

/*
 * GlobalProtect client for the OpenConnect VPN ACAP, built on libopenconnect.
 *
 * The app bridge (OpenConnect_VPN) runs this and talks to it over the
 * standard streams:
 *   stdout  lines starting with "@" are events for the bridge; other lines are
 *           log text (error-level log text goes to stderr)
 *   stdin   "key value" setup lines up to "begin", then answers to login forms
 * Values on stdin and in bridge-parsed events are percent-encoded. Secrets (the
 * password and a saved session cookie) only ever arrive on stdin.
 *
 * In interactive mode every login form the portal sends (credentials, one-time
 * codes, challenges, SSO) is relayed to the settings page and answered there.
 * Unattended starts only use the stored username and password or a saved
 * session cookie, and report "login_required" when the portal wants more.
 *
 * The same binary is the HIP report generator: OpenConnect runs its CSD
 * wrapper with --cookie/--client-ip/--md5, and the report describes the camera
 * as it is (model, serial number, AXIS OS version, interfaces).
 */

#define _GNU_SOURCE
#include <openconnect.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

/* ── string buffer ───────────────────────────────────────────────────────── */

typedef struct {
    char *s;
    size_t len, cap;
} Buf;

static void buf_add(Buf *b, const char *s, size_t n) {
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 256;
        while (cap < b->len + n + 1)
            cap *= 2;
        char *grown = realloc(b->s, cap);
        if (!grown)
            abort();
        b->s = grown;
        b->cap = cap;
    }
    memcpy(b->s + b->len, s, n);
    b->len += n;
    b->s[b->len] = '\0';
}

static void buf_str(Buf *b, const char *s) { buf_add(b, s ? s : "", strlen(s ? s : "")); }

static void buf_printf(Buf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void buf_printf(Buf *b, const char *fmt, ...) {
    char *tmp = NULL;
    va_list ap;
    va_start(ap, fmt);
    int n = vasprintf(&tmp, fmt, ap);
    va_end(ap);
    if (n < 0)
        abort();
    buf_add(b, tmp, (size_t)n);
    free(tmp);
}

static void buf_json(Buf *b, const char *s) {
    buf_str(b, "\"");
    for (const unsigned char *p = (const unsigned char *)(s ? s : ""); *p; p++) {
        if (*p == '"' || *p == '\\')
            buf_printf(b, "\\%c", *p);
        else if (*p < 0x20)
            buf_printf(b, "\\u%04x", *p);
        else
            buf_add(b, (const char *)p, 1);
    }
    buf_str(b, "\"");
}

static void buf_xml(Buf *b, const char *s) {
    for (const char *p = s ? s : ""; *p; p++) {
        switch (*p) {
        case '&':
            buf_str(b, "&amp;");
            break;
        case '<':
            buf_str(b, "&lt;");
            break;
        case '>':
            buf_str(b, "&gt;");
            break;
        case '"':
            buf_str(b, "&quot;");
            break;
        default:
            buf_add(b, p, 1);
        }
    }
}

/* ── percent encoding ────────────────────────────────────────────────────── */

static char *pct_encode(const char *s) {
    Buf b = {0};
    buf_str(&b, "");
    for (const unsigned char *p = (const unsigned char *)(s ? s : ""); *p; p++) {
        if (isalnum(*p) || strchr("-._~", *p))
            buf_add(&b, (const char *)p, 1);
        else
            buf_printf(&b, "%%%02X", *p);
    }
    return b.s;
}

static int hexval(int c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    c = tolower(c);
    return (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
}

static char *pct_decode(const char *s, size_t n) {
    Buf b = {0};
    buf_str(&b, "");
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '+') {
            buf_add(&b, " ", 1);
        } else if (s[i] == '%' && i + 2 < n && hexval(s[i + 1]) >= 0 && hexval(s[i + 2]) >= 0) {
            char c = (char)(hexval(s[i + 1]) * 16 + hexval(s[i + 2]));
            buf_add(&b, &c, 1);
            i += 2;
        } else {
            buf_add(&b, s + i, 1);
        }
    }
    return b.s;
}

/* Decodes %XX only: in a callback link '+' is base64, not a space. */
static char *pct_decode_keep_plus(const char *s, size_t n) {
    Buf b = {0};
    buf_str(&b, "");
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '%' && i + 2 < n && hexval(s[i + 1]) >= 0 && hexval(s[i + 2]) >= 0) {
            char c = (char)(hexval(s[i + 1]) * 16 + hexval(s[i + 2]));
            buf_add(&b, &c, 1);
            i += 2;
        } else {
            buf_add(&b, s + i, 1);
        }
    }
    return b.s;
}

/* Value of "name" in an application/x-www-form-urlencoded string, or NULL. */
static char *form_value(const char *form, const char *name) {
    size_t nlen = strlen(name);
    const char *p = form;
    while (p && *p) {
        const char *end = strchr(p, '&');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        const char *eq = memchr(p, '=', len);
        if (eq) {
            char *key = pct_decode(p, (size_t)(eq - p));
            int match = strlen(key) == nlen && !strcmp(key, name);
            free(key);
            if (match)
                return pct_decode(eq + 1, len - (size_t)(eq - p) - 1);
        }
        p = end ? end + 1 : NULL;
    }
    return NULL;
}

/* ── base64 (standard and URL-safe, padding optional) ────────────────────── */

static char *base64_decode(const char *s) {
    Buf b = {0};
    buf_str(&b, "");
    unsigned int acc = 0;
    int bits = 0;
    for (const char *p = s; *p; p++) {
        int v;
        if (*p >= 'A' && *p <= 'Z')
            v = *p - 'A';
        else if (*p >= 'a' && *p <= 'z')
            v = *p - 'a' + 26;
        else if (*p >= '0' && *p <= '9')
            v = *p - '0' + 52;
        else if (*p == '+' || *p == '-')
            v = 62;
        else if (*p == '/' || *p == '_')
            v = 63;
        else if (*p == '=' || isspace((unsigned char)*p))
            continue;
        else
            break;
        acc = (acc << 6) | (unsigned int)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            char c = (char)((acc >> bits) & 0xff);
            buf_add(&b, &c, 1);
        }
    }
    return b.s;
}

/* ── state ───────────────────────────────────────────────────────────────── */

static struct openconnect_info *vpn;
static int cmd_fd = -1;
static int interactive;
static char *cfg_user, *cfg_password, *cfg_cookie, *cfg_connect_url;
static char *cfg_gateway, *cfg_pin, *tun_script;
/* Password typed on the settings page, reused for the gateway's own login
 * form after a portal challenge. Memory only. */
static char *typed_password;
static int form_seq;
static int credentials_rejected; /* the server just refused the credentials */
/* The login form that carries the SSO result, so its field can be named for
 * the kind of result the portal handed back. */
static struct oc_auth_form *sso_form;
/* Tracks the verdict on the last SSO result sent. A gateway refusing the
 * portal's result afterwards (then asking for its own sign-in) is normal
 * GlobalProtect behaviour, not a rejection of what the user sent. */
static int sso_awaiting_verdict;
static int sso_result_rejected;
static int portal_accepted;
static unsigned long last_result_hash;

/* FNV-1a: a fingerprint for the log and for spotting a resubmitted result,
 * without logging the result itself. */
static unsigned long fingerprint(const char *s) {
    unsigned long h = 2166136261UL;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        h = ((h ^ *p) * 16777619UL) & 0xffffffffUL;
    return h;
}

/* Host of the page the result came from: the bookmarklet sends that page's
 * URL as its first line. Diagnostic only. */
static void source_host(const char *text, char *out, size_t size) {
    snprintf(out, size, "pasted");
    const char *p = strstr(text, "://");
    if (!p || p - text > 8)
        return;
    p += 3;
    size_t len = strcspn(p, "/?#:\r\n \t");
    if (len > 0 && len < size)
        snprintf(out, size, "%.*s", (int)len, p);
}
static const char *exit_reason;

static void emit(const char *event, const char *payload) {
    if (payload && *payload)
        printf("@%s %s\n", event, payload);
    else
        printf("@%s\n", event);
    fflush(stdout);
}

/* Reads one stdin line; returns the command word and points *arg at the rest. */
static char *read_command(char **arg) {
    static char *line;
    static size_t cap;
    ssize_t n = getline(&line, &cap, stdin);
    if (n <= 0)
        return NULL;
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
        line[--n] = '\0';
    char *space = strchr(line, ' ');
    if (space) {
        *space = '\0';
        *arg = space + 1;
    } else {
        *arg = line + n;
    }
    return line;
}

/* ── callbacks ───────────────────────────────────────────────────────────── */

static void progress_cb(void *priv, int level, const char *fmt, ...) {
    (void)priv;
    if (level > PRG_INFO)
        return;
    char msg[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    FILE *out = level == PRG_ERR ? stderr : stdout;
    char *save = NULL;
    for (char *line = strtok_r(msg, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        /* Never let server-supplied text look like an event. */
        fprintf(out, "%s%s\n", line[0] == '@' ? " " : "", line);
        fflush(out);

        if (strstr(line, "detected dead peer") || !strncmp(line, "Packet receive error", 20) ||
            strstr(line, "rekey due"))
            emit("reconnecting", NULL);
        else if (strstr(line, "ESP session established"))
            emit("esp", NULL);
        else if (strstr(line, "Unexpected 512 result") || strstr(line, "Unexpected 401 result") ||
                 strstr(line, "Unexpected 403 result") || strstr(line, "Invalid username or password") ||
                 strstr(line, "Authentication failed")) {
            credentials_rejected = 1;
            if (sso_awaiting_verdict)
                sso_result_rejected = 1;
            sso_awaiting_verdict = 0;
        } else if (strstr(line, "gateway servers available") || strstr(line, "Portal reports GlobalProtect version") ||
                   strstr(line, "GlobalProtect login returned")) {
            if (strstr(line, "gateway servers available") || strstr(line, "Portal reports"))
                portal_accepted = 1;
            sso_awaiting_verdict = 0;
        }
    }
}

static int validate_cert_cb(void *priv, const char *reason) {
    (void)priv;
    if (cfg_pin && *cfg_pin && openconnect_check_peer_cert_hash(vpn, cfg_pin) == 0)
        return 0;
    char *pin = pct_encode(openconnect_get_peer_cert_hash(vpn));
    char *why = pct_encode(reason);
    Buf b = {0};
    buf_printf(&b, "%s %s", pin, why);
    emit("untrusted", b.s);
    free(b.s);
    free(pin);
    free(why);
    exit_reason = "untrusted";
    return -EINVAL;
}

static int is_user_field(const struct oc_form_opt *opt) {
    return opt->name && (!strncasecmp(opt->name, "user", 4) || !strncasecmp(opt->name, "uname", 5));
}

static int select_choice(struct oc_form_opt_select *sel, const char *wanted) {
    for (int i = 0; wanted && *wanted && i < sel->nr_choices; i++) {
        struct oc_choice *c = sel->choices[i];
        if ((c->name && !strcasecmp(c->name, wanted)) || (c->label && !strcasecmp(c->label, wanted))) {
            sel->form._value = c->name;
            return 1;
        }
    }
    return 0;
}

/* A follow-up prompt (OTP code, RADIUS challenge) after the first login form.
 * libopenconnect marks its field as a password when it has no token generator,
 * but it must never be answered with the account password. */
static int is_challenge(const struct oc_auth_form *form) {
    return form->auth_id && !strcmp(form->auth_id, "_challenge");
}

static const char *opt_type_name(int type) {
    switch (type) {
    case OC_FORM_OPT_PASSWORD:
        return "password";
    case OC_FORM_OPT_TOKEN:
        return "token";
    case OC_FORM_OPT_SELECT:
        return "select";
    default:
        return "text";
    }
}

static int relayed_opt(const struct oc_form_opt *opt) {
    return opt->name && !(opt->flags & OC_FORM_OPT_IGNORE) && opt->type != OC_FORM_OPT_HIDDEN &&
           opt->type != OC_FORM_OPT_SSO_TOKEN && opt->type != OC_FORM_OPT_SSO_USER;
}

/* Sends the form to the settings page and applies the answer. */
static int ask_user(struct oc_auth_form *form) {
    int id = ++form_seq;
    int challenge = is_challenge(form);
    Buf b = {0};
    buf_printf(&b, "{\"id\":%d,\"auth_id\":", id);
    buf_json(&b, form->auth_id);
    buf_str(&b, ",\"banner\":");
    buf_json(&b, form->banner);
    buf_str(&b, ",\"message\":");
    buf_json(&b, form->message);
    buf_str(&b, ",\"error\":");
    buf_json(&b, form->error ? form->error
                             : (credentials_rejected ? "The portal rejected the credentials. Try again." : ""));
    buf_str(&b, ",\"fields\":[");
    int first = 1;
    for (struct oc_form_opt *opt = form->opts; opt; opt = opt->next) {
        if (!relayed_opt(opt))
            continue;
        buf_str(&b, first ? "{\"name\":" : ",{\"name\":");
        first = 0;
        buf_json(&b, opt->name);
        buf_str(&b, ",\"label\":");
        buf_json(&b, opt->label);
        buf_printf(&b, ",\"type\":\"%s\",\"value\":",
                   challenge && opt->type == OC_FORM_OPT_PASSWORD ? "token" : opt_type_name(opt->type));
        /* Never echo a password back to the browser. */
        buf_json(&b, opt->type == OC_FORM_OPT_TEXT || opt->type == OC_FORM_OPT_SELECT ? opt->_value : "");
        if (opt->type == OC_FORM_OPT_SELECT) {
            struct oc_form_opt_select *sel = (struct oc_form_opt_select *)opt;
            buf_str(&b, ",\"choices\":[");
            for (int i = 0; i < sel->nr_choices; i++) {
                buf_str(&b, i ? ",{\"name\":" : "{\"name\":");
                buf_json(&b, sel->choices[i]->name);
                buf_str(&b, ",\"label\":");
                buf_json(&b, sel->choices[i]->label);
                buf_str(&b, "}");
            }
            buf_str(&b, "]");
        }
        buf_str(&b, "}");
    }
    buf_str(&b, "]}");
    emit("form", b.s);
    free(b.s);

    for (;;) {
        char *arg = NULL;
        char *cmd = read_command(&arg);
        if (!cmd || !strcmp(cmd, "cancel")) {
            exit_reason = "cancelled";
            return OC_FORM_RESULT_CANCELLED;
        }
        if (strcmp(cmd, "answer"))
            continue;
        char *form_id = form_value(arg, "form_id");
        int matches = form_id && atoi(form_id) == id;
        free(form_id);
        if (!matches)
            continue;
        for (struct oc_form_opt *opt = form->opts; opt; opt = opt->next) {
            if (!relayed_opt(opt))
                continue;
            char *value = form_value(arg, opt->name);
            if (!value)
                continue;
            if (opt->type == OC_FORM_OPT_SELECT) {
                select_choice((struct oc_form_opt_select *)opt, value);
            } else {
                openconnect_set_option_value(opt, value);
                if (opt->type == OC_FORM_OPT_PASSWORD && *value && !challenge) {
                    free(typed_password);
                    typed_password = strdup(value);
                }
            }
            free(value);
        }
        credentials_rejected = 0;
        return OC_FORM_RESULT_OK;
    }
}

static int process_form_cb(void *priv, struct oc_auth_form *form) {
    (void)priv;
    int has_sso = 0, missing = 0;
    const char *password = typed_password ? typed_password : cfg_password;

    /* The portal's gateway list. */
    if (form->authgroup_opt) {
        struct oc_form_opt_select *sel = form->authgroup_opt;
        if (!select_choice(sel, cfg_gateway) && sel->nr_choices > 0)
            sel->form._value = sel->choices[0]->name;
    }

    for (struct oc_form_opt *opt = form->opts; opt; opt = opt->next) {
        if (opt->flags & OC_FORM_OPT_IGNORE)
            continue;
        switch (opt->type) {
        case OC_FORM_OPT_SSO_TOKEN:
        case OC_FORM_OPT_SSO_USER:
            has_sso = 1;
            break;
        case OC_FORM_OPT_SELECT:
            if ((struct oc_form_opt_select *)opt != form->authgroup_opt && !opt->_value) {
                struct oc_form_opt_select *sel = (struct oc_form_opt_select *)opt;
                if (sel->nr_choices > 1)
                    missing++;
                else if (sel->nr_choices == 1)
                    opt->_value = sel->choices[0]->name;
            }
            break;
        case OC_FORM_OPT_TEXT:
            if (is_user_field(opt) && cfg_user && *cfg_user)
                openconnect_set_option_value(opt, cfg_user);
            else if (!opt->_value || !*opt->_value)
                missing++;
            break;
        case OC_FORM_OPT_PASSWORD:
            /* After a rejection the stored password is known to be wrong. */
            if (password && *password && !credentials_rejected && !is_challenge(form))
                openconnect_set_option_value(opt, password);
            else
                missing++;
            break;
        case OC_FORM_OPT_TOKEN:
            missing++;
            break;
        default:
            break;
        }
    }

    if (has_sso) {
        sso_form = form;
        if (!interactive) {
            emit("login_required", "sso");
            exit_reason = "login_required";
            return OC_FORM_RESULT_CANCELLED;
        }
        return OC_FORM_RESULT_OK; /* libopenconnect now calls open_webview_cb */
    }
    if (!missing)
        return OC_FORM_RESULT_OK;
    if (!interactive) {
        if (credentials_rejected) {
            exit_reason = "auth_rejected";
        } else {
            emit("login_required", "form");
            exit_reason = "login_required";
        }
        return OC_FORM_RESULT_CANCELLED;
    }
    return ask_user(form);
}

/* Text between <tag> and </tag>, e.g. from the portal's final SAML page. */
static char *tag_value(const char *text, const char *tag) {
    char open[64], close[64];
    snprintf(open, sizeof(open), "<%s>", tag);
    snprintf(close, sizeof(close), "</%s>", tag);
    const char *start = strstr(text, open);
    if (!start)
        return NULL;
    start += strlen(open);
    const char *end = strstr(start, close);
    if (!end || end == start)
        return NULL;
    return strndup(start, (size_t)(end - start));
}

/* Pulls the SAML result out of whatever the user pasted or the bookmarklet sent:
 * the portal's final page (result in an HTML comment), a globalprotectcallback:
 * link carrying that page in base64, or a Cloud Authentication Service (CAS)
 * callback "cas-as=1&un=<user>&token=<token>". *field is the login form field
 * the portal expects the result in: prelogin-cookie, portal-userauthcookie or
 * (CAS) token. */
static int parse_sso_result(const char *text, char **user, char **field, char **value) {
    char *decoded = NULL;
    const char *source = text;
    const char *cb = strstr(text, "globalprotectcallback:");
    const char *cas = strstr(text, "cas-as");
    if (cb || cas) {
        const char *start = cb ? cb + strlen("globalprotectcallback:") : cas;
        while (*start == '/')
            start++;
        size_t len = strcspn(start, " \t\r\n\"'<>");
        char *payload = pct_decode_keep_plus(start, len);
        if (!strncmp(payload, "cas-as", 6)) {
            /* Undo one more level of encoding some portals apply. */
            char *query = strchr(payload, '&') ? strdup(payload) : pct_decode(payload, strlen(payload));
            *user = form_value(query, "un");
            *value = form_value(query, "token");
            *field = strdup("token");
            free(query);
            free(payload);
            return *user && *value && **value;
        }
        decoded = base64_decode(payload);
        free(payload);
        source = decoded;
    }

    *user = tag_value(source, "saml-username");
    if ((*value = tag_value(source, "prelogin-cookie")))
        *field = strdup("prelogin-cookie");
    else if ((*value = tag_value(source, "portal-userauthcookie")))
        *field = strdup("portal-userauthcookie");
    free(decoded);
    if (!*user && *value && cfg_user && *cfg_user)
        *user = strdup(cfg_user);
    return *user && *value;
}

/* libopenconnect submits the SSO result in the form's secret field, which it
 * names "passwd"; portals only accept it under the name of the result. */
static void name_sso_field(const char *field) {
    for (struct oc_form_opt *opt = sso_form ? sso_form->opts : NULL; opt; opt = opt->next) {
        if (opt->type == OC_FORM_OPT_SSO_TOKEN) {
            char *name = strdup(field);
            if (name) {
                free(opt->name);
                opt->name = name;
            }
        }
    }
}

static int open_webview_cb(struct openconnect_info *info, const char *uri, void *priv) {
    (void)priv;
    /* libopenconnect calls this even after process_form_cb cancelled the form,
     * so an unattended start must refuse here rather than wait for a person. */
    if (!interactive) {
        exit_reason = "login_required";
        return -EINTR;
    }
    /* Called again after the server refused the result the user sent: stop
     * here so a broken hand-off cannot turn into a series of failed sign-ins. */
    if (sso_result_rejected) {
        exit_reason = "sso_rejected";
        return -EINTR;
    }
    Buf b = {0};
    buf_printf(&b, "{\"id\":%d,\"stage\":\"%s\",\"url\":", ++form_seq, portal_accepted ? "gateway" : "portal");
    buf_json(&b, uri);
    buf_str(&b, "}");
    emit("sso", b.s);
    free(b.s);

    for (;;) {
        char *arg = NULL;
        char *cmd = read_command(&arg);
        if (!cmd || !strcmp(cmd, "cancel")) {
            exit_reason = "cancelled";
            return -EINTR;
        }
        if (strcmp(cmd, "sso"))
            continue;
        char *text = pct_decode(arg, strlen(arg));
        char *user = NULL, *field = NULL, *value = NULL;
        char host[128];
        source_host(text, host, sizeof(host));
        int ok = parse_sso_result(text, &user, &field, &value);
        free(text);
        if (ok && fingerprint(value) == last_result_hash) {
            printf("Single sign-on result from %s is the one already used; not sending it again\n", host);
            fflush(stdout);
            char *msg = pct_encode("This is the result of the previous sign-in, which cannot be used again. Click "
                                   "Open the sign-in page, finish that sign-in, then send the new result.");
            emit("sso_error", msg);
            free(msg);
            free(user);
            free(field);
            free(value);
            continue;
        }
        if (ok) {
            /* libopenconnect only recognises the cookie header names; the
             * form field is renamed to what the portal expects below. */
            const char *header = strcmp(field, "token") ? field : "prelogin-cookie";
            const char *headers[] = {"saml-username", user, header, value, NULL};
            struct oc_webview_result result = {.uri = NULL, .cookies = NULL, .headers = headers};
            ok = openconnect_webview_load_changed(info, &result) == 0;
            if (ok) {
                name_sso_field(field);
                sso_awaiting_verdict = 1;
                last_result_hash = fingerprint(value);
                printf("Single sign-on result received for %s (%s from %s, fingerprint %08lx)\n", user, field, host,
                       last_result_hash);
                fflush(stdout);
            }
        }
        free(user);
        free(field);
        free(value);
        if (ok) {
            emit("sso_done", NULL);
            return 0;
        }
        char *msg = pct_encode("No GlobalProtect sign-in result found. Finish the sign-in first, then send the "
                               "final page.");
        emit("sso_error", msg);
        free(msg);
    }
}

static void setup_tun_cb(void *priv) {
    (void)priv;
    if (openconnect_setup_tun_script(vpn, tun_script)) {
        fprintf(stderr, "Set up tun script failed\n");
        return;
    }
    const struct oc_ip_info *ip = NULL;
    openconnect_get_ip_info(vpn, &ip, NULL, NULL);
    char payload[128];
    snprintf(payload, sizeof(payload), "%s %d", ip && ip->addr ? ip->addr : "-", ip ? ip->mtu : 0);
    emit("up", payload);
}

static void reconnected_cb(void *priv) {
    (void)priv;
    emit("reconnected", NULL);
}

/* SIGTERM detaches (the gateway session stays valid for the next start);
 * SIGUSR1 logs out of the gateway. */
static void on_signal(int sig) {
    char cmd = sig == SIGUSR1 ? OC_CMD_CANCEL : OC_CMD_DETACH;
    if (cmd_fd >= 0 && write(cmd_fd, &cmd, 1) < 0) {
        /* nothing useful to do in a signal handler */
    }
}

/* ── HIP report ──────────────────────────────────────────────────────────── */

static const char *env_or(const char *name, const char *fallback) {
    const char *v = getenv(name);
    return v && *v ? v : fallback;
}

static void hip_interfaces(Buf *b) {
    struct ifaddrs *list = NULL;
    if (getifaddrs(&list) != 0)
        return;
    char done[16][IF_NAMESIZE];
    int ndone = 0;
    for (struct ifaddrs *ifa = list; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || (ifa->ifa_flags & IFF_LOOPBACK) || !(ifa->ifa_flags & IFF_UP))
            continue;
        int seen = 0;
        for (int i = 0; i < ndone; i++)
            seen |= !strcmp(done[i], ifa->ifa_name);
        if (seen || ndone == 16)
            continue;
        snprintf(done[ndone++], IF_NAMESIZE, "%s", ifa->ifa_name);

        char mac[32] = "", path[96];
        snprintf(path, sizeof(path), "/sys/class/net/%s/address", ifa->ifa_name);
        FILE *f = fopen(path, "r");
        if (f) {
            if (fgets(mac, sizeof(mac), f))
                mac[strcspn(mac, "\r\n")] = '\0';
            fclose(f);
        }
        for (char *p = mac; *p; p++)
            *p = *p == ':' ? '-' : (char)toupper((unsigned char)*p);

        Buf v4 = {0}, v6 = {0};
        buf_str(&v4, "");
        buf_str(&v6, "");
        for (struct ifaddrs *a = list; a; a = a->ifa_next) {
            if (!a->ifa_addr || !a->ifa_name || strcmp(a->ifa_name, ifa->ifa_name))
                continue;
            char text[INET6_ADDRSTRLEN];
            if (a->ifa_addr->sa_family == AF_INET &&
                inet_ntop(AF_INET, &((struct sockaddr_in *)a->ifa_addr)->sin_addr, text, sizeof(text))) {
                buf_str(&v4, "\t\t\t\t\t\t<entry name=\"");
                buf_xml(&v4, text);
                buf_str(&v4, "\"/>\n");
            } else if (a->ifa_addr->sa_family == AF_INET6 &&
                       inet_ntop(AF_INET6, &((struct sockaddr_in6 *)a->ifa_addr)->sin6_addr, text, sizeof(text))) {
                buf_str(&v6, "\t\t\t\t\t\t<entry name=\"");
                buf_xml(&v6, text);
                buf_str(&v6, "\"/>\n");
            }
        }
        buf_str(b, "\t\t\t\t<entry name=\"");
        buf_xml(b, ifa->ifa_name);
        buf_str(b, "\">\n\t\t\t\t\t<description>");
        buf_xml(b, env_or("GP_HIP_MODEL", "Axis device"));
        buf_str(b, " ");
        buf_xml(b, ifa->ifa_name);
        buf_str(b, "</description>\n\t\t\t\t\t<mac-address>");
        buf_xml(b, mac);
        buf_str(b, "</mac-address>\n\t\t\t\t\t<ip-address>\n");
        buf_str(b, v4.s);
        buf_str(b, "\t\t\t\t\t</ip-address>\n\t\t\t\t\t<ipv6-address>\n");
        buf_str(b, v6.s);
        buf_str(b, "\t\t\t\t\t</ipv6-address>\n\t\t\t\t</entry>\n");
        free(v4.s);
        free(v6.s);
    }
    freeifaddrs(list);
}

static int hip_report(int argc, char **argv) {
    const char *cookie = "", *ip = "", *ipv6 = "", *md5 = "";
    for (int i = 1; i + 1 < argc; i++) {
        if (!strcmp(argv[i], "--cookie"))
            cookie = argv[++i];
        else if (!strcmp(argv[i], "--client-ip"))
            ip = argv[++i];
        else if (!strcmp(argv[i], "--client-ipv6"))
            ipv6 = argv[++i];
        else if (!strcmp(argv[i], "--md5"))
            md5 = argv[++i];
    }
    char *user = form_value(cookie, "user");
    char *domain = form_value(cookie, "domain");
    char host[HOST_NAME_MAX + 1] = "";
    gethostname(host, sizeof(host) - 1);

    const char *serial = env_or("GP_HIP_SERIAL", "");
    char os[256];
    snprintf(os, sizeof(os), "%s %s (%s)", env_or("GP_HIP_OS_NAME", "AXIS OS"), env_or("GP_HIP_OS_VERSION", ""),
             env_or("GP_HIP_MODEL", "Axis device"));
    char now[32];
    time_t t = time(NULL);
    strftime(now, sizeof(now), "%m/%d/%Y %H:%M:%S", localtime(&t));

    Buf b = {0};
    buf_str(&b, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<hip-report name=\"hip-report\">\n\t<md5-sum>");
    buf_xml(&b, md5);
    buf_str(&b, "</md5-sum>\n\t<user-name>");
    buf_xml(&b, user);
    buf_str(&b, "</user-name>\n\t<domain>");
    buf_xml(&b, domain);
    buf_str(&b, "</domain>\n\t<host-name>");
    buf_xml(&b, host);
    buf_str(&b, "</host-name>\n\t<host-id>");
    buf_xml(&b, serial);
    buf_str(&b, "</host-id>\n\t<ip-address>");
    buf_xml(&b, ip);
    buf_str(&b, "</ip-address>\n\t<ipv6-address>");
    buf_xml(&b, ipv6);
    buf_str(&b, "</ipv6-address>\n\t<generate-time>");
    buf_xml(&b, now);
    buf_str(&b, "</generate-time>\n\t<hip-report-version>4</hip-report-version>\n\t<categories>\n"
                "\t\t<entry name=\"host-info\">\n\t\t\t<client-version>");
    buf_xml(&b, env_or("APP_VERSION", ""));
    buf_str(&b, "</client-version>\n\t\t\t<os>");
    buf_xml(&b, os);
    buf_str(&b, "</os>\n\t\t\t<os-vendor>");
    buf_xml(&b, env_or("GP_HIP_VENDOR", "Axis Communications"));
    buf_str(&b, "</os-vendor>\n\t\t\t<domain>");
    buf_xml(&b, domain);
    buf_str(&b, "</domain>\n\t\t\t<host-name>");
    buf_xml(&b, host);
    buf_str(&b, "</host-name>\n\t\t\t<host-id>");
    buf_xml(&b, serial);
    buf_str(&b, "</host-id>\n\t\t\t<serial-number>");
    buf_xml(&b, serial);
    buf_str(&b, "</serial-number>\n\t\t\t<network-interface>\n");
    hip_interfaces(&b);
    buf_str(&b, "\t\t\t</network-interface>\n\t\t</entry>\n");
    /* The camera runs none of these, so each category is reported empty. */
    static const char *const categories[] = {"anti-malware", "disk-backup",      "disk-encryption",
                                             "firewall",     "patch-management", "data-loss-prevention"};
    for (size_t i = 0; i < sizeof(categories) / sizeof(categories[0]); i++)
        buf_printf(&b, "\t\t<entry name=\"%s\">\n\t\t\t<list/>\n\t\t</entry>\n", categories[i]);
    buf_str(&b, "\t</categories>\n</hip-report>\n");

    fputs(b.s, stdout);
    free(b.s);
    free(user);
    free(domain);
    return 0;
}

/* ── main ────────────────────────────────────────────────────────────────── */

static void usage(void) {
    fprintf(stderr, "usage: gp-client --server HOST[:PORT] --tun-script PATH [--gateway-only] [--gateway NAME]\n"
                    "                 [--os OS] [--servercert PIN] [--cafile FILE] [--certificate FILE]\n");
}

static int finish(int code) {
    emit("exit", exit_reason ? exit_reason : (code ? "error" : "ok"));
    if (vpn)
        openconnect_vpninfo_free(vpn);
    return code;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--md5"))
            return hip_report(argc, argv);
    }

    const char *server = NULL, *os = "linux", *cafile = NULL, *certificate = NULL;
    int gateway_only = 0;
    for (int i = 1; i < argc; i++) {
        const char *next = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(argv[i], "--gateway-only"))
            gateway_only = 1;
        else if (!next)
            break;
        else if (!strcmp(argv[i], "--server"))
            server = argv[++i];
        else if (!strcmp(argv[i], "--gateway"))
            cfg_gateway = argv[++i];
        else if (!strcmp(argv[i], "--os"))
            os = argv[++i];
        else if (!strcmp(argv[i], "--servercert"))
            cfg_pin = argv[++i];
        else if (!strcmp(argv[i], "--cafile"))
            cafile = argv[++i];
        else if (!strcmp(argv[i], "--certificate"))
            certificate = argv[++i];
        else if (!strcmp(argv[i], "--tun-script"))
            tun_script = argv[++i];
    }
    if (!server || !tun_script) {
        usage();
        return 2;
    }

    for (;;) {
        char *arg = NULL;
        char *cmd = read_command(&arg);
        if (!cmd || !strcmp(cmd, "begin"))
            break;
        char *value = pct_decode(arg, strlen(arg));
        if (!strcmp(cmd, "user"))
            cfg_user = value;
        else if (!strcmp(cmd, "password"))
            cfg_password = value;
        else if (!strcmp(cmd, "cookie"))
            cfg_cookie = value;
        else if (!strcmp(cmd, "connect_url"))
            cfg_connect_url = value;
        else {
            if (!strcmp(cmd, "mode"))
                interactive = !strcmp(value, "interactive");
            free(value);
        }
    }

    signal(SIGPIPE, SIG_IGN);
    openconnect_init_ssl();
    vpn = openconnect_vpninfo_new("AnyConnect-compatible OpenConnect VPN Agent", validate_cert_cb, NULL,
                                  process_form_cb, progress_cb, NULL);
    if (!vpn) {
        fprintf(stderr, "Failed to allocate the VPN context\n");
        return finish(1);
    }
    openconnect_set_loglevel(vpn, PRG_INFO);
    if (openconnect_set_protocol(vpn, "gp") || openconnect_set_reported_os(vpn, os)) {
        fprintf(stderr, "Failed to select the GlobalProtect protocol\n");
        return finish(1);
    }
    openconnect_set_webview_callback(vpn, open_webview_cb);
    openconnect_set_setup_tun_handler(vpn, setup_tun_cb);
    openconnect_set_reconnected_handler(vpn, reconnected_cb);
    if (cafile)
        openconnect_set_cafile(vpn, cafile);
    if (certificate)
        openconnect_set_client_cert(vpn, certificate, NULL);

    char self[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (n > 0) {
        self[n] = '\0';
        openconnect_setup_csd(vpn, getuid(), 1, self);
    }

    cmd_fd = openconnect_setup_cmd_pipe(vpn);

    int reused = cfg_cookie && *cfg_cookie && cfg_connect_url && *cfg_connect_url;
    if (reused) {
        if (openconnect_parse_url(vpn, cfg_connect_url) || openconnect_set_cookie(vpn, cfg_cookie)) {
            exit_reason = "cookie_rejected";
            return finish(1);
        }
        printf("Reusing the saved gateway session\n");
        fflush(stdout);
    } else {
        Buf url = {0};
        buf_printf(&url, "%s%s%s", strstr(server, "://") ? "" : "https://", server, gateway_only ? "/gateway" : "");
        int bad = openconnect_parse_url(vpn, url.s);
        free(url.s);
        if (bad) {
            fprintf(stderr, "Invalid server address\n");
            return finish(1);
        }
        if (openconnect_obtain_cookie(vpn)) {
            if (!exit_reason && credentials_rejected)
                exit_reason = "auth_rejected";
            fprintf(stderr, "Failed to complete authentication\n");
            return finish(1);
        }
        char *cookie = pct_encode(openconnect_get_cookie(vpn));
        char *connect_url = pct_encode(openconnect_get_connect_url(vpn));
        Buf b = {0};
        buf_printf(&b, "%s %s", cookie, connect_url);
        emit("cookie", b.s);
        free(b.s);
        free(cookie);
        free(connect_url);
    }

    int ret = openconnect_make_cstp_connection(vpn);
    if (ret) {
        /* Only an explicit refusal means the saved session is gone; a network
         * error must keep it for the next attempt. */
        if (ret == -EPERM)
            exit_reason = "cookie_rejected";
        fprintf(stderr, "Creating the gateway connection failed\n");
        return finish(1);
    }
    if (openconnect_setup_dtls(vpn, 60)) {
        openconnect_disable_dtls(vpn);
        fprintf(stderr, "Set up UDP failed; using SSL instead\n");
    }

    struct sigaction sa = {0};
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);

    do {
        ret = openconnect_mainloop(vpn, 300, 10);
    } while (ret == 0);

    switch (ret) {
    case -EPERM:
        exit_reason = "cookie_rejected";
        break;
    case -EINTR:
        exit_reason = "logged_out";
        break;
    case -ECONNABORTED:
        exit_reason = "detached";
        break;
    default:
        exit_reason = "error";
        break;
    }
    return finish(ret == -EINTR || ret == -ECONNABORTED ? 0 : 1);
}
