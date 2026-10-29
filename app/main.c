// SPDX-License-Identifier: BSD-3-Clause

/*
 * OpenConnect VPN ACAP bridge.
 *
 * Owns the manifest.json parameters and supervises lib/gp-client, the
 * libopenconnect-based GlobalProtect client. The client runs fully in
 * userspace: its tun script (lib/tun-script.sh) execs the Go netstack sidecar,
 * so there is no root and no kernel TUN.
 *
 * Signing in: the client relays every login form the portal sends (password,
 * one-time code, challenge, SSO) as an event; the settings page shows it and
 * the answer is passed back on the client's stdin. The resulting gateway
 * session cookie is kept (0600) and reused for unattended reconnects and
 * restarts until the gateway ends the session; only then is a new sign-in
 * needed. A stored password, if any, lets the camera sign in again by itself
 * when the portal asks for nothing else.
 *
 * Serves the settings, status, sign-in and certificate endpoints on
 * 127.0.0.1:2210, behind the camera's authenticated reverse proxy as
 * /local/OpenConnect_VPN/api/..., so the UI works on devices without
 * /axis-cgi/param.cgi. The loopback port must be unique per device; see
 * PARAM_CGI_FALLBACK.md.
 */

#include <axsdk/axparameter.h>
#include <errno.h>
#include <fcntl.h>
#include <gio/gio.h>
#include <glib-unix.h>
#include <glib/gstdio.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define APP_NAME "OpenConnect_VPN"
#define APP_DIR "/usr/local/packages/" APP_NAME
#define LIB_DIR APP_DIR "/lib"
#define STATE_DIR APP_DIR "/localdata"
#define CLIENT_BIN LIB_DIR "/gp-client"
#define TUN_SCRIPT LIB_DIR "/tun-script.sh"
#define BUNDLED_CA LIB_DIR "/ca-bundle.crt"
#define CLIENT_CERT_FILE STATE_DIR "/client.pem"
#define CA_FILE STATE_DIR "/ca.pem"
#define SESSION_FILE STATE_DIR "/session"
#define SIDECAR_PIDFILE STATE_DIR "/sidecar.pid"
#define SETTINGS_HTTP_PORT 2210
#define MAX_REQUEST (256 * 1024)
#define MAX_PEM (128 * 1024)
#define CONFIG_DEBOUNCE_MS 1000
#define STOP_GRACE_MS 8000
#define RETRY_MIN_S 15
#define RETRY_MAX_S 600
/* Long pause after a rejected stored password: portals commonly lock accounts
 * after a handful of failures, and a camera retrying forever would trip that. */
#define AUTH_RETRY_S 900
#define STABLE_SESSION_S 120
/* A sign-in left waiting on the settings page is abandoned after this. */
#define LOGIN_TIMEOUT_S 600

typedef struct {
    const char *name;
    const char *fallback;
    gboolean secret;
    char *value;
} Parameter;

/* Must stay in sync with paramConfig in manifest.json. */
static Parameter parameters[] = {
    {"Enabled", "no", FALSE, NULL},
    {"Server", "", FALSE, NULL},
    {"ServerType", "portal", FALSE, NULL},
    {"Gateway", "", FALSE, NULL},
    {"Username", "", FALSE, NULL},
    {"Password", "", TRUE, NULL},
    {"ServerCert", "", FALSE, NULL},
    {"ReportedOs", "linux", FALSE, NULL},
    {"HttpProxyPort", "28080", FALSE, NULL},
    {"Socks5Port", "21080", FALSE, NULL},
    {"ForwardPorts", "80,443,554", FALSE, NULL},
    {"KeepAliveMinutes", "0", FALSE, NULL},
};

static AXParameter *parameter_handle;
static GMainLoop *main_loop;
static gboolean shutting_down;

/* The camera's own details, for the HIP report. */
static char *device_model;
static char *device_serial;
static char *device_os_version;

/* ── client process state ────────────────────────────────────────────────── */

static GPid client_pid = -1;
static int client_stdin = -1;
static gboolean client_interactive;
static gboolean client_used_session;
static gboolean restart_pending;
static gboolean restart_interactive;
static guint config_timer;
static guint retry_timer;
static guint kill_timer;
static guint login_timer;
static guint retry_delay = RETRY_MIN_S;
static gint64 retry_at;        /* monotonic seconds, 0 when no retry is queued */
static gint64 connected_mono;  /* monotonic seconds, 0 when not connected */
static gint64 connected_since; /* wall-clock seconds for the UI */

static const char *state = "starting";
static char *vpn_ip;
static char *last_error;
static char *untrusted_pin;
static char *untrusted_reason;
static char *proxy_warning;
static char *exit_reason;
static char *login_needed;  /* "form" or "sso" after an unattended start needed a person */
static char *pending_login; /* JSON of the form or SSO step waiting on the settings page */
static char *sso_error;
static gboolean esp_up;

static void set_text(char **field, const char *value) {
    g_free(*field);
    *field = (value && *value) ? g_strdup(value) : NULL;
}

static gint64 now_mono(void) { return g_get_monotonic_time() / G_USEC_PER_SEC; }

static gboolean state_is(const char *expected) { return g_strcmp0(state, expected) == 0; }

/* ── parameters ──────────────────────────────────────────────────────────── */

static Parameter *find_parameter(const char *name) {
    for (gsize i = 0; i < G_N_ELEMENTS(parameters); i++) {
        if (g_strcmp0(parameters[i].name, name) == 0)
            return &parameters[i];
    }
    return NULL;
}

/* Parameter callbacks report a qualified name such as root.APPNAME.Enabled. */
static Parameter *find_parameter_suffix(const char *qualified_name) {
    const char *last = strrchr(qualified_name, '.');
    return find_parameter(last ? last + 1 : qualified_name);
}

static const char *param(const char *name) {
    Parameter *parameter = find_parameter(name);
    if (!parameter)
        return "";
    return parameter->value ? parameter->value : parameter->fallback;
}

static gboolean param_is(const char *name, const char *expected) { return g_strcmp0(param(name), expected) == 0; }

/* Restricts enum-like parameters so a typo cannot produce a broken command line. */
static const char *param_choice(const char *name, const char *const *allowed) {
    const char *value = param(name);
    for (gsize i = 0; allowed[i]; i++) {
        if (g_strcmp0(value, allowed[i]) == 0)
            return value;
    }
    return allowed[0];
}

static const char *const server_types[] = {"portal", "gateway", NULL};
static const char *const reported_oses[] = {"linux", "linux-64", "win", "mac-intel", NULL};

static const char *port_or(const char *name, const char *fallback) {
    const char *value = param(name);
    char *end = NULL;
    long port = strtol(value, &end, 10);
    if (!*value || (end && *end) || port < 1 || port > 65535)
        return fallback;
    return value;
}

/* Keep-alive interval in minutes, 0 (off) when unset or invalid. */
static long keepalive_minutes(void) {
    const char *value = param("KeepAliveMinutes");
    char *end = NULL;
    long minutes = strtol(value, &end, 10);
    if (!*value || (end && *end) || minutes < 1)
        return 0;
    return MIN(minutes, 1440);
}

/* Host part of the Server setting, for the keep-alive DNS query. */
static gchar *server_host(void) {
    const char *server = param("Server");
    const char *start = strstr(server, "://");
    start = start ? start + 3 : server;
    gsize length = strcspn(start, ":/?#");
    return g_strndup(start, length);
}

static void load_parameter(Parameter *parameter) {
    GError *error = NULL;
    gchar *value = NULL;

    if (ax_parameter_get(parameter_handle, parameter->name, &value, &error)) {
        g_free(parameter->value);
        parameter->value = g_strdup(value ? value : "");
        g_free(value);
    } else {
        syslog(LOG_WARNING, "read parameter %s failed: %s", parameter->name, error ? error->message : "unknown error");
        if (!parameter->value)
            parameter->value = g_strdup(parameter->fallback);
    }
    g_clear_error(&error);
}

/* Reads a device parameter outside the app's own group (root.Brand.*). */
static char *read_device_parameter(const char *name) {
    GError *error = NULL;
    gchar *value = NULL;
    char *result = NULL;
    if (ax_parameter_get(parameter_handle, name, &value, &error) && value && *value)
        result = g_strdup(g_strstrip(value));
    g_free(value);
    g_clear_error(&error);
    return result;
}

static void load_device_info(void) {
    device_model = read_device_parameter("root.Brand.ProdFullName");
    if (!device_model)
        device_model = read_device_parameter("root.Brand.ProdShortName");
    device_serial = read_device_parameter("root.Properties.System.SerialNumber");
    device_os_version = read_device_parameter("root.Properties.Firmware.Version");
    if (!device_os_version) {
        gchar *release = NULL;
        if (g_file_get_contents("/etc/os-release", &release, NULL, NULL)) {
            const char *v = strstr(release, "VERSION_ID=");
            if (v) {
                v += strlen("VERSION_ID=");
                device_os_version = g_strndup(v, strcspn(v, "\r\n"));
                g_strdelimit(device_os_version, "\"", ' ');
                g_strstrip(device_os_version);
            }
            g_free(release);
        }
    }
    syslog(LOG_INFO, "device: %s, serial %s, AXIS OS %s", device_model ? device_model : "unknown",
           device_serial ? device_serial : "unknown", device_os_version ? device_os_version : "unknown");
}

/* ── files ───────────────────────────────────────────────────────────────── */

/* Owner-only from creation; fchmod also tightens a file left by an older build. */
static gboolean write_private_file(const char *path, const char *data, gsize length) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        syslog(LOG_ERR, "cannot write %s: %s", path, strerror(errno));
        return FALSE;
    }
    fchmod(fd, 0600);
    gsize written = 0;
    while (written < length) {
        ssize_t n = write(fd, data + written, length - written);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            syslog(LOG_ERR, "write %s failed: %s", path, strerror(errno));
            close(fd);
            return FALSE;
        }
        written += (gsize)n;
    }
    close(fd);
    return TRUE;
}

static gboolean file_exists(const char *path) { return g_file_test(path, G_FILE_TEST_IS_REGULAR); }

/* Prefer the camera's own CA bundle; fall back to the one shipped in lib/. */
static const char *system_ca_file(void) {
    static const char *const candidates[] = {
        "/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem", "/etc/pki/tls/certs/ca-bundle.crt", BUNDLED_CA, NULL,
    };
    for (gsize i = 0; candidates[i]; i++) {
        if (file_exists(candidates[i]))
            return candidates[i];
    }
    return NULL;
}

/* Kills a netstack sidecar left behind by a client that died uncleanly.
 * The pid is checked against /proc so a recycled pid is never signalled. */
static void kill_stale_sidecar(void) {
    gchar *text = NULL;
    if (!g_file_get_contents(SIDECAR_PIDFILE, &text, NULL, NULL))
        return;
    long pid = strtol(text, NULL, 10);
    g_free(text);
    g_unlink(SIDECAR_PIDFILE);
    if (pid <= 1)
        return;

    gchar *cmdline_path = g_strdup_printf("/proc/%ld/cmdline", pid);
    gchar *cmdline = NULL;
    gsize length = 0;
    if (g_file_get_contents(cmdline_path, &cmdline, &length, NULL) && length > 0 &&
        g_strstr_len(cmdline, (gssize)length, "netstack_proxy")) {
        syslog(LOG_INFO, "stopping leftover netstack sidecar (pid %ld)", pid);
        kill((pid_t)pid, SIGTERM);
    }
    g_free(cmdline);
    g_free(cmdline_path);
}

/* ── saved gateway session ───────────────────────────────────────────────── */

/* A session belongs to one server, account and gateway choice. */
static gchar *session_key(void) {
    return g_strdup_printf("%s|%s|%s|%s", param("Server"), param_choice("ServerType", server_types), param("Gateway"),
                           param("Username"));
}

static void clear_session(void) {
    if (file_exists(SESSION_FILE))
        syslog(LOG_INFO, "saved gateway session discarded");
    g_unlink(SESSION_FILE);
}

static void save_session(const char *cookie, const char *connect_url) {
    gchar *key = session_key();
    gchar *text = g_strdup_printf("%s\n%s\n%s\n", key, cookie, connect_url);
    if (write_private_file(SESSION_FILE, text, strlen(text)))
        syslog(LOG_INFO, "gateway session saved for unattended reconnects");
    memset(text, 0, strlen(text));
    g_free(text);
    g_free(key);
}

/* Returns the saved cookie and connect URL if they belong to the current settings. */
static gboolean load_session(gchar **cookie, gchar **connect_url) {
    gchar *text = NULL;
    gboolean ok = FALSE;
    if (!g_file_get_contents(SESSION_FILE, &text, NULL, NULL))
        return FALSE;
    gchar **lines = g_strsplit(text, "\n", 4);
    gchar *key = session_key();
    if (lines[0] && lines[1] && lines[2] && *lines[1] && *lines[2] && g_strcmp0(lines[0], key) == 0) {
        *cookie = g_strdup(lines[1]);
        *connect_url = g_strdup(lines[2]);
        ok = TRUE;
    }
    g_free(key);
    g_strfreev(lines);
    memset(text, 0, strlen(text));
    g_free(text);
    return ok;
}

/* ── client supervision ──────────────────────────────────────────────────── */

static void start_client(gboolean interactive);

static void reset_session_info(void) {
    set_text(&vpn_ip, NULL);
    esp_up = FALSE;
    connected_mono = 0;
    connected_since = 0;
}

static void cancel_login_timer(void) {
    if (login_timer)
        g_source_remove(login_timer);
    login_timer = 0;
}

static void clear_pending_login(void) {
    cancel_login_timer();
    set_text(&pending_login, NULL);
    set_text(&sso_error, NULL);
}

static gboolean on_retry_timeout(gpointer user_data) {
    (void)user_data;
    retry_timer = 0;
    retry_at = 0;
    start_client(FALSE);
    return G_SOURCE_REMOVE;
}

static void cancel_retry(void) {
    if (retry_timer)
        g_source_remove(retry_timer);
    retry_timer = 0;
    retry_at = 0;
}

static void schedule_retry(guint seconds) {
    cancel_retry();
    retry_at = now_mono() + seconds;
    retry_timer = g_timeout_add_seconds(seconds, on_retry_timeout, NULL);
    syslog(LOG_INFO, "reconnecting in %u s", seconds);
}

static void write_client(const char *line) {
    if (client_stdin < 0)
        return;
    gchar *text = g_strconcat(line, "\n", NULL);
    gsize length = strlen(text), written = 0;
    while (written < length) {
        ssize_t n = write(client_stdin, text + written, length - written);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        written += (gsize)n;
    }
    memset(text, 0, length);
    g_free(text);
}

static void write_client_value(const char *key, const char *value) {
    gchar *escaped = g_uri_escape_string(value ? value : "", NULL, FALSE);
    gchar *line = g_strconcat(key, " ", escaped, NULL);
    write_client(line);
    memset(escaped, 0, strlen(escaped));
    memset(line, 0, strlen(line));
    g_free(escaped);
    g_free(line);
}

static gboolean on_kill_timeout(gpointer user_data) {
    (void)user_data;
    kill_timer = 0;
    if (client_pid > 0) {
        syslog(LOG_WARNING, "client did not exit in time, sending SIGKILL");
        kill(-client_pid, SIGKILL);
        kill(client_pid, SIGKILL);
    }
    kill_stale_sidecar();
    return G_SOURCE_REMOVE;
}

/* SIGTERM detaches and keeps the gateway session valid for the next start;
 * SIGUSR1 logs out of the gateway. Both stop the netstack sidecar. */
static void stop_client(gboolean logout) {
    if (client_pid <= 0)
        return;
    kill(client_pid, logout ? SIGUSR1 : SIGTERM);
    if (!kill_timer)
        kill_timer = g_timeout_add(STOP_GRACE_MS, on_kill_timeout, NULL);
}

static void restart_client(gboolean interactive) {
    cancel_retry();
    retry_delay = RETRY_MIN_S;
    if (client_pid > 0) {
        restart_pending = TRUE;
        restart_interactive = interactive;
        stop_client(FALSE);
    } else {
        start_client(interactive);
    }
}

static gboolean on_login_timeout(gpointer user_data) {
    (void)user_data;
    login_timer = 0;
    syslog(LOG_INFO, "sign-in was not completed in time; cancelling it");
    write_client("cancel");
    return G_SOURCE_REMOVE;
}

static void await_login(const char *json) {
    set_text(&pending_login, json);
    set_text(&sso_error, NULL);
    state = "awaiting_input";
    cancel_login_timer();
    login_timer = g_timeout_add_seconds(LOGIN_TIMEOUT_S, on_login_timeout, NULL);
}

static void mark_connected(void) {
    state = "connected";
    set_text(&last_error, NULL);
}

/* Splits "a b" into two percent-decoded parts. */
static void split_pair(const char *payload, gchar **first, gchar **second) {
    const char *space = strchr(payload, ' ');
    gchar *a = g_strndup(payload, space ? (gsize)(space - payload) : strlen(payload));
    *first = g_uri_unescape_string(a, NULL);
    *second = space ? g_uri_unescape_string(space + 1, NULL) : NULL;
    g_free(a);
}

static void handle_event(const char *line) {
    const char *space = strchr(line, ' ');
    gchar *event = g_strndup(line, space ? (gsize)(space - line) : strlen(line));
    const char *payload = space ? space + 1 : "";

    if (g_strcmp0(event, "untrusted") == 0) {
        gchar *pin = NULL, *reason = NULL;
        split_pair(payload, &pin, &reason);
        set_text(&untrusted_pin, pin);
        set_text(&untrusted_reason, reason);
        g_free(pin);
        g_free(reason);
    } else if (g_strcmp0(event, "form") == 0 || g_strcmp0(event, "sso") == 0) {
        syslog(LOG_INFO, "sign-in waiting for %s on the settings page",
               g_strcmp0(event, "sso") == 0 ? "single sign-on" : "input");
        await_login(payload);
    } else if (g_strcmp0(event, "sso_error") == 0) {
        gchar *message = g_uri_unescape_string(payload, NULL);
        set_text(&sso_error, message);
        g_free(message);
    } else if (g_strcmp0(event, "sso_done") == 0) {
        clear_pending_login();
        state = "connecting";
    } else if (g_strcmp0(event, "login_required") == 0) {
        set_text(&login_needed, payload);
    } else if (g_strcmp0(event, "cookie") == 0) {
        gchar *cookie = NULL, *url = NULL;
        split_pair(payload, &cookie, &url);
        if (cookie && url)
            save_session(cookie, url);
        if (cookie)
            memset(cookie, 0, strlen(cookie));
        g_free(cookie);
        g_free(url);
        clear_pending_login();
        state = "connecting";
    } else if (g_strcmp0(event, "up") == 0) {
        gchar **parts = g_strsplit(payload, " ", 2);
        set_text(&vpn_ip, parts[0] && g_strcmp0(parts[0], "-") ? parts[0] : NULL);
        g_strfreev(parts);
        clear_pending_login();
        mark_connected();
        connected_mono = now_mono();
        connected_since = (gint64)time(NULL);
        set_text(&untrusted_pin, NULL);
        set_text(&untrusted_reason, NULL);
    } else if (g_strcmp0(event, "reconnecting") == 0) {
        if (state_is("connected")) {
            state = "reconnecting";
            esp_up = FALSE;
            set_text(&last_error, "The connection to the gateway was lost; reconnecting.");
        }
    } else if (g_strcmp0(event, "reconnected") == 0) {
        if (state_is("reconnecting")) {
            mark_connected();
            syslog(LOG_INFO, "tunnel re-established");
        }
    } else if (g_strcmp0(event, "esp") == 0) {
        esp_up = TRUE;
    } else if (g_strcmp0(event, "exit") == 0) {
        set_text(&exit_reason, payload);
    }
    g_free(event);
}

static void handle_output_line(char *line, gboolean is_stderr) {
    g_strchomp(line);
    if (!*line)
        return;
    if (line[0] == '@') {
        handle_event(line + 1);
        return;
    }

    syslog(is_stderr ? LOG_WARNING : LOG_INFO, "client: %s", line);

    const char *trimmed = line;
    while (*trimmed == ' ' || *trimmed == '\t')
        trimmed++;
    if (g_str_has_prefix(trimmed, "netstack: outbound ")) {
        const char *detail = trimmed + strlen("netstack: outbound ");
        if (proxy_warning) {
            gchar *both = g_strconcat(proxy_warning, "; ", detail, NULL);
            set_text(&proxy_warning, both);
            g_free(both);
        } else {
            set_text(&proxy_warning, detail);
        }
        return;
    }
    /* Warnings after connecting are noise for the status card. */
    if (is_stderr && !state_is("connected") && !state_is("reconnecting"))
        set_text(&last_error, trimmed);
}

static gboolean on_client_output(GIOChannel *channel, GIOCondition condition, gpointer user_data);

/* The output channels of the running client, kept so the exit handler can
 * drain lines still queued in the pipes before it classifies the exit. */
static GIOChannel *client_channels[2];
static guint client_watches[2];

/* Reads every complete line currently buffered; returns FALSE on EOF/error. */
static gboolean read_available_lines(GIOChannel *channel, gboolean is_stderr) {
    for (;;) {
        gchar *line = NULL;
        GIOStatus status = g_io_channel_read_line(channel, &line, NULL, NULL, NULL);
        if (status == G_IO_STATUS_NORMAL && line) {
            handle_output_line(line, is_stderr);
            g_free(line);
            continue;
        }
        g_free(line);
        return status == G_IO_STATUS_AGAIN;
    }
}

static void close_output(int index) {
    if (!client_channels[index])
        return;
    if (client_watches[index])
        g_source_remove(client_watches[index]);
    client_watches[index] = 0;
    g_io_channel_shutdown(client_channels[index], FALSE, NULL);
    g_io_channel_unref(client_channels[index]);
    client_channels[index] = NULL;
}

static gboolean on_client_output(GIOChannel *channel, GIOCondition condition, gpointer user_data) {
    int index = GPOINTER_TO_INT(user_data);

    if ((condition & G_IO_IN) && read_available_lines(channel, index == 1))
        return G_SOURCE_CONTINUE;
    if (!(condition & (G_IO_IN | G_IO_HUP | G_IO_ERR)))
        return G_SOURCE_CONTINUE;

    /* EOF: the source is removed by returning FALSE, so forget its id first. */
    client_watches[index] = 0;
    close_output(index);
    return G_SOURCE_REMOVE;
}

static void watch_output(int fd, int index) {
    close_output(index);
    GIOChannel *channel = g_io_channel_unix_new(fd);
    g_io_channel_set_encoding(channel, NULL, NULL);
    g_io_channel_set_flags(channel, G_IO_FLAG_NONBLOCK, NULL);
    client_channels[index] = channel;
    client_watches[index] =
        g_io_add_watch(channel, G_IO_IN | G_IO_HUP | G_IO_ERR, on_client_output, GINT_TO_POINTER(index));
}

static void on_client_exit(GPid pid, gint status, gpointer user_data) {
    (void)user_data;
    g_spawn_close_pid(pid);
    client_pid = -1;
    if (kill_timer) {
        g_source_remove(kill_timer);
        kill_timer = 0;
    }
    /* The exit can be reported before the last output lines are read. The pipes
     * may stay open (the sidecar inherits them), so only drain what is queued. */
    for (int i = 0; i < 2; i++) {
        if (client_channels[i])
            read_available_lines(client_channels[i], i == 1);
        close_output(i);
    }
    if (client_stdin >= 0) {
        close(client_stdin);
        client_stdin = -1;
    }
    kill_stale_sidecar();
    clear_pending_login();

    gint64 session = connected_mono ? now_mono() - connected_mono : 0;
    reset_session_info();
    const char *reason = exit_reason ? exit_reason : "error";
    syslog(LOG_INFO, "client exited (%s, status %d) after %" G_GINT64_FORMAT " s connected", reason,
           WIFEXITED(status) ? WEXITSTATUS(status) : -1, session);

    if (shutting_down)
        return;
    if (restart_pending) {
        restart_pending = FALSE;
        start_client(restart_interactive);
        restart_interactive = FALSE;
        return;
    }
    if (!param_is("Enabled", "yes")) {
        state = "disabled";
        return;
    }

    /* Holds wait for the user: retrying cannot help until something changes. */
    if (g_strcmp0(reason, "untrusted") == 0) {
        state = "cert_untrusted";
        gchar *message = g_strdup_printf("The server certificate failed verification%s%s. Trust its pin or "
                                         "upload the issuing CA.",
                                         untrusted_reason ? ": " : "", untrusted_reason ? untrusted_reason : "");
        set_text(&last_error, message);
        g_free(message);
        syslog(LOG_WARNING, "server certificate not trusted; waiting for ServerCert or a CA upload");
        return;
    }
    if (g_strcmp0(reason, "sso_rejected") == 0) {
        state = "login_required";
        set_text(&last_error, "The portal did not accept the single sign-on result. Nothing is retried "
                              "automatically; check the account's VPN access before signing in again.");
        syslog(LOG_WARNING, "portal rejected the single sign-on result; not retrying");
        return;
    }
    if (g_strcmp0(reason, "login_required") == 0 || g_strcmp0(reason, "cancelled") == 0) {
        state = "login_required";
        if (g_strcmp0(reason, "cancelled") == 0)
            set_text(&last_error, "The sign-in was cancelled or not completed in time.");
        else if (g_strcmp0(login_needed, "sso") == 0)
            set_text(&last_error, "The portal uses single sign-on. Click Sign in to complete it in your browser.");
        else
            set_text(&last_error, "The portal asks for more than the stored credentials (for example a one-time "
                                  "code). Click Sign in.");
        syslog(LOG_WARNING, "sign-in needed on the settings page");
        return;
    }
    if (g_strcmp0(reason, "auth_rejected") == 0) {
        state = "auth_failed";
        set_text(&last_error, "The portal rejected the stored credentials.");
        if (*param("Password")) {
            syslog(LOG_WARNING, "credentials rejected; pausing before retrying to avoid an account lockout");
            schedule_retry(AUTH_RETRY_S);
        } else {
            state = "login_required";
        }
        return;
    }
    if (g_strcmp0(reason, "cookie_rejected") == 0) {
        /* The gateway ended the session (expired or logged out): sign in again,
         * which only stays unattended if the stored credentials are enough. */
        clear_session();
        syslog(LOG_INFO, "gateway session ended; signing in again");
        start_client(FALSE);
        return;
    }
    if (g_strcmp0(reason, "logged_out") == 0) {
        state = "disabled";
        return;
    }

    if (session >= STABLE_SESSION_S)
        retry_delay = RETRY_MIN_S;
    state = "disconnected";
    schedule_retry(retry_delay);
    retry_delay = MIN(retry_delay * 2, RETRY_MAX_S);
}

static void child_setup(gpointer user_data) {
    (void)user_data;
    setpgid(0, 0);
}

static void add_arg(GPtrArray *argv, const char *format, ...) G_GNUC_PRINTF(2, 3);
static void add_arg(GPtrArray *argv, const char *format, ...) {
    va_list args;
    va_start(args, format);
    g_ptr_array_add(argv, g_strdup_vprintf(format, args));
    va_end(args);
}

static gchar **client_environment(void) {
    gchar **envp = g_get_environ();
    envp = g_environ_setenv(envp, "GP_HTTP_PORT", port_or("HttpProxyPort", "28080"), TRUE);
    envp = g_environ_setenv(envp, "GP_SOCKS_PORT", port_or("Socks5Port", "21080"), TRUE);
    envp =
        g_environ_setenv(envp, "GP_FORWARD_PORTS", *param("ForwardPorts") ? param("ForwardPorts") : "80,443,554", TRUE);
    envp = g_environ_setenv(envp, "GP_SIDECAR_PIDFILE", SIDECAR_PIDFILE, TRUE);
    gchar *keepalive = g_strdup_printf("%ld", keepalive_minutes());
    gchar *keepalive_host = server_host();
    envp = g_environ_setenv(envp, "GP_KEEPALIVE_MINUTES", keepalive, TRUE);
    envp = g_environ_setenv(envp, "GP_KEEPALIVE_HOST", keepalive_host, TRUE);
    g_free(keepalive);
    g_free(keepalive_host);
    envp = g_environ_setenv(envp, "GP_HIP_MODEL", device_model ? device_model : "Axis device", TRUE);
    envp = g_environ_setenv(envp, "GP_HIP_SERIAL", device_serial ? device_serial : "", TRUE);
    envp = g_environ_setenv(envp, "GP_HIP_OS_NAME", "AXIS OS", TRUE);
    envp = g_environ_setenv(envp, "GP_HIP_OS_VERSION", device_os_version ? device_os_version : "", TRUE);
    envp = g_environ_setenv(envp, "GP_HIP_VENDOR", "Axis Communications", TRUE);
    const char *ca_file = system_ca_file();
    if (ca_file)
        envp = g_environ_setenv(envp, "SSL_CERT_FILE", ca_file, FALSE);
    if (g_file_test("/etc/ssl/certs", G_FILE_TEST_IS_DIR))
        envp = g_environ_setenv(envp, "SSL_CERT_DIR", "/etc/ssl/certs", FALSE);
    return envp;
}

static void start_client(gboolean interactive) {
    if (shutting_down || client_pid > 0)
        return;
    cancel_retry();
    reset_session_info();
    clear_pending_login();
    set_text(&last_error, NULL);
    set_text(&untrusted_pin, NULL);
    set_text(&untrusted_reason, NULL);
    set_text(&proxy_warning, NULL);
    set_text(&exit_reason, NULL);
    set_text(&login_needed, NULL);

    if (!param_is("Enabled", "yes")) {
        state = "disabled";
        return;
    }
    if (!*param("Server")) {
        state = "waiting_config";
        set_text(&last_error, "Set the portal or gateway address.");
        return;
    }
    if (g_access(CLIENT_BIN, X_OK) != 0) {
        state = "error";
        set_text(&last_error, "The GlobalProtect client is missing from the package.");
        syslog(LOG_ERR, "%s is missing or not executable", CLIENT_BIN);
        return;
    }

    g_mkdir_with_parents(STATE_DIR, 0755);
    kill_stale_sidecar();

    const char *server_type = param_choice("ServerType", server_types);
    GPtrArray *argv = g_ptr_array_new_with_free_func(g_free);
    add_arg(argv, "%s", CLIENT_BIN);
    add_arg(argv, "--server");
    add_arg(argv, "%s", param("Server"));
    if (g_strcmp0(server_type, "gateway") == 0)
        add_arg(argv, "--gateway-only");
    if (*param("Gateway")) {
        add_arg(argv, "--gateway");
        add_arg(argv, "%s", param("Gateway"));
    }
    add_arg(argv, "--os");
    add_arg(argv, "%s", param_choice("ReportedOs", reported_oses));
    if (*param("ServerCert")) {
        add_arg(argv, "--servercert");
        add_arg(argv, "%s", param("ServerCert"));
    }
    if (file_exists(CA_FILE)) {
        add_arg(argv, "--cafile");
        add_arg(argv, "%s", CA_FILE);
    }
    if (file_exists(CLIENT_CERT_FILE)) {
        add_arg(argv, "--certificate");
        add_arg(argv, "%s", CLIENT_CERT_FILE);
    }
    add_arg(argv, "--tun-script");
    add_arg(argv, "%s", TUN_SCRIPT);
    g_ptr_array_add(argv, NULL);

    gchar **envp = client_environment();
    GError *error = NULL;
    gint in_fd = -1, out_fd = -1, err_fd = -1;
    GPid pid = -1;
    gboolean spawned = g_spawn_async_with_pipes(STATE_DIR, (gchar **)argv->pdata, envp, G_SPAWN_DO_NOT_REAP_CHILD,
                                                child_setup, NULL, &pid, &in_fd, &out_fd, &err_fd, &error);
    g_strfreev(envp);
    g_ptr_array_free(argv, TRUE);

    if (!spawned) {
        state = "error";
        set_text(&last_error, error ? error->message : "failed to start the GlobalProtect client");
        syslog(LOG_ERR, "failed to start the client: %s", error ? error->message : "unknown error");
        g_clear_error(&error);
        schedule_retry(retry_delay);
        retry_delay = MIN(retry_delay * 2, RETRY_MAX_S);
        return;
    }

    client_pid = pid;
    client_stdin = in_fd;
    client_interactive = interactive;
    fcntl(in_fd, F_SETFD, FD_CLOEXEC);

    gchar *cookie = NULL, *connect_url = NULL;
    client_used_session = !interactive && load_session(&cookie, &connect_url);
    if (*param("Username"))
        write_client_value("user", param("Username"));
    if (*param("Password"))
        write_client_value("password", param("Password"));
    if (client_used_session) {
        write_client_value("cookie", cookie);
        write_client_value("connect_url", connect_url);
        memset(cookie, 0, strlen(cookie));
    }
    g_free(cookie);
    g_free(connect_url);
    write_client_value("mode", interactive ? "interactive" : "unattended");
    write_client("begin");

    state = "connecting";
    syslog(LOG_INFO, "client started (pid %d) for %s %s, %s", (int)pid, server_type, param("Server"),
           interactive ? "interactive sign-in" : (client_used_session ? "saved session" : "unattended sign-in"));

    watch_output(out_fd, 0);
    watch_output(err_fd, 1);
    g_child_watch_add(pid, on_client_exit, NULL);
}

static gchar *applied_session_key;

static gboolean on_config_timeout(gpointer user_data) {
    (void)user_data;
    config_timer = 0;
    gchar *key = session_key();
    gboolean account_changed = g_strcmp0(key, applied_session_key) != 0;
    g_free(applied_session_key);
    applied_session_key = key;

    if (!param_is("Enabled", "yes")) {
        syslog(LOG_INFO, "VPN disabled; signing out");
        cancel_retry();
        restart_pending = FALSE;
        clear_session();
        if (client_pid > 0)
            stop_client(TRUE);
        else
            state = "disabled";
        return G_SOURCE_REMOVE;
    }
    if (account_changed)
        clear_session();
    syslog(LOG_INFO, "configuration changed, reconnecting");
    restart_client(FALSE);
    return G_SOURCE_REMOVE;
}

/* param.cgi updates fire one callback per parameter; coalesce them. */
static void schedule_config_apply(void) {
    if (config_timer)
        g_source_remove(config_timer);
    config_timer = g_timeout_add(CONFIG_DEBOUNCE_MS, on_config_timeout, NULL);
}

static void on_parameter_changed(const gchar *name, const gchar *value, gpointer user_data) {
    (void)user_data;
    Parameter *parameter = find_parameter_suffix(name);
    if (!parameter || g_strcmp0(parameter->value, value) == 0)
        return;

    g_free(parameter->value);
    parameter->value = g_strdup(value ? value : "");
    syslog(LOG_INFO, "parameter %s changed", parameter->name);
    schedule_config_apply();
}

/* ── JSON helpers ────────────────────────────────────────────────────────── */

static void json_append_escaped(GString *out, const char *value) {
    for (const char *cursor = value ? value : ""; *cursor; cursor++) {
        switch (*cursor) {
        case '"':
            g_string_append(out, "\\\"");
            break;
        case '\\':
            g_string_append(out, "\\\\");
            break;
        case '\n':
            g_string_append(out, "\\n");
            break;
        case '\r':
            g_string_append(out, "\\r");
            break;
        case '\t':
            g_string_append(out, "\\t");
            break;
        default:
            if ((unsigned char)*cursor < 0x20)
                g_string_append_printf(out, "\\u%04x", (unsigned char)*cursor);
            else
                g_string_append_c(out, *cursor);
        }
    }
}

static void json_string_field(GString *out, const char *name, const char *value) {
    if (out->len > 1)
        g_string_append_c(out, ',');
    g_string_append_c(out, '"');
    json_append_escaped(out, name);
    g_string_append(out, "\":\"");
    json_append_escaped(out, value ? value : "");
    g_string_append_c(out, '"');
}

/* Embeds JSON produced by the client as-is (it escapes its own strings). */
static void json_raw_field(GString *out, const char *name, const char *json) {
    if (out->len > 1)
        g_string_append_c(out, ',');
    g_string_append_printf(out, "\"%s\":%s", name, json && *json == '{' ? json : "null");
}

/* g_string_free(out, FALSE) inlines to g_string_free_and_steal() on newer
 * headers and breaks on AXIS OS 11.x runtimes; copy the buffer instead. */
static gchar *json_finish(GString *out) {
    g_string_append_c(out, '}');
    gchar *json = g_strdup(out->str);
    g_string_free(out, TRUE);
    return json;
}

/* Secrets are never returned; the UI only learns whether one is stored. */
static gchar *settings_json(void) {
    GString *out = g_string_new("{");
    for (gsize i = 0; i < G_N_ELEMENTS(parameters); i++) {
        const char *value = param(parameters[i].name);
        if (parameters[i].secret) {
            gchar *key = g_strconcat(parameters[i].name, "IsSet", NULL);
            json_string_field(out, key, *value ? "yes" : "no");
            g_free(key);
        } else {
            json_string_field(out, parameters[i].name, value);
        }
    }
    json_string_field(out, "ClientCertIsSet", file_exists(CLIENT_CERT_FILE) ? "yes" : "no");
    json_string_field(out, "CaIsSet", file_exists(CA_FILE) ? "yes" : "no");
    return json_finish(out);
}

static gchar *status_json(void) {
    GString *out = g_string_new("{");
    gint64 retry_in = retry_at ? MAX(retry_at - now_mono(), 0) : 0;
    gchar *number;

    json_string_field(out, "state", state);
    json_string_field(out, "vpn_ip", vpn_ip);
    json_string_field(out, "transport", state_is("connected") ? (esp_up ? "ESP (UDP)" : "SSL (TCP)") : "");
    number = g_strdup_printf("%" G_GINT64_FORMAT, connected_since);
    json_string_field(out, "connected_since", connected_since ? number : "");
    g_free(number);
    number = g_strdup_printf("%" G_GINT64_FORMAT, retry_in);
    json_string_field(out, "retry_in", retry_in ? number : "");
    g_free(number);
    json_string_field(out, "last_error", last_error);
    json_string_field(out, "untrusted_pin", untrusted_pin);
    json_string_field(out, "untrusted_reason", untrusted_reason);
    json_string_field(out, "warning", proxy_warning);
    json_string_field(out, "session", file_exists(SESSION_FILE) ? "saved" : "");
    json_raw_field(out, "login", pending_login);
    json_string_field(out, "sso_error", sso_error);
    json_string_field(out, "http_port", port_or("HttpProxyPort", "28080"));
    json_string_field(out, "socks_port", port_or("Socks5Port", "21080"));
    json_string_field(out, "forward_ports", *param("ForwardPorts") ? param("ForwardPorts") : "80,443,554");
    return json_finish(out);
}

/* ── settings / sign-in HTTP server (127.0.0.1:SETTINGS_HTTP_PORT) ───────── */

static gchar *url_decode(const char *value, gsize length) {
    GString *out = g_string_sized_new(length);

    for (gsize i = 0; i < length; i++) {
        if (value[i] == '+') {
            g_string_append_c(out, ' ');
        } else if (value[i] == '%' && i + 2 < length && g_ascii_isxdigit(value[i + 1]) &&
                   g_ascii_isxdigit(value[i + 2])) {
            g_string_append_c(out,
                              (gchar)(g_ascii_xdigit_value(value[i + 1]) * 16 + g_ascii_xdigit_value(value[i + 2])));
            i += 2;
        } else {
            g_string_append_c(out, value[i]);
        }
    }

    gchar *decoded = g_strdup(out->str);
    g_string_free(out, TRUE);
    return decoded;
}

/* Applies an application/x-www-form-urlencoded body, ignoring unknown keys. */
static gboolean apply_settings_body(const char *body) {
    gchar **pairs = g_strsplit(body ? body : "", "&", -1);
    gboolean changed = FALSE;

    for (gchar **pair = pairs; *pair; pair++) {
        gchar *separator = strchr(*pair, '=');
        if (!separator)
            continue;

        gchar *name = url_decode(*pair, (gsize)(separator - *pair));
        gchar *value = url_decode(separator + 1, strlen(separator + 1));
        g_strstrip(value);
        Parameter *parameter = find_parameter(name);
        GError *error = NULL;

        if (!parameter) {
            syslog(LOG_WARNING, "rejected unknown parameter %s", name);
        } else if (g_strcmp0(parameter->value, value) == 0) {
            /* No change. */
        } else if (ax_parameter_set(parameter_handle, parameter->name, value, TRUE, &error)) {
            g_free(parameter->value);
            parameter->value = g_strdup(value);
            changed = TRUE;
        } else {
            syslog(LOG_ERR, "write parameter %s failed: %s", parameter->name, error ? error->message : "unknown error");
        }

        g_clear_error(&error);
        g_free(name);
        g_free(value);
    }

    g_strfreev(pairs);
    return changed;
}

/* Stores (or, for an empty body, removes) an uploaded PEM file. */
static const char *store_pem(const char *path, const char *body, gsize length, const char *what) {
    if (length == 0) {
        g_unlink(path);
        syslog(LOG_INFO, "%s removed", what);
        return NULL;
    }
    if (length > MAX_PEM)
        return "file too large";
    if (!g_strstr_len(body, (gssize)length, "-----BEGIN "))
        return "not a PEM file";
    g_mkdir_with_parents(STATE_DIR, 0755);
    if (!write_private_file(path, body, length))
        return "could not store the file";
    syslog(LOG_INFO, "%s uploaded (%zu bytes)", what, length);
    return NULL;
}

static void send_response(GOutputStream *out, const char *status, const char *content_type, const char *body) {
    gchar *response = g_strdup_printf("HTTP/1.1 %s\r\n"
                                      "Content-Type: %s\r\n"
                                      "Content-Length: %zu\r\n"
                                      "Cache-Control: no-store\r\n"
                                      "Connection: close\r\n"
                                      "\r\n"
                                      "%s",
                                      status, content_type, strlen(body), body);
    g_output_stream_write_all(out, response, strlen(response), NULL, NULL, NULL);
    g_free(response);
}

static void send_result(GOutputStream *out, const char *error) {
    if (error) {
        gchar *body = g_strdup_printf("{\"status\":\"error\",\"error\":\"%s\"}", error);
        send_response(out, "400 Bad Request", "application/json", body);
        g_free(body);
    } else {
        send_response(out, "200 OK", "application/json", "{\"status\":\"ok\"}");
    }
}

static gsize header_content_length(const char *headers, gsize length) {
    gchar *lower = g_ascii_strdown(headers, (gssize)length);
    gchar *field = strstr(lower, "\r\ncontent-length:");
    gsize value = field ? (gsize)g_ascii_strtoull(field + strlen("\r\ncontent-length:"), NULL, 10) : 0;
    g_free(lower);
    return value;
}

/* The last path segment, without a query string: "/x/api/status?a" -> "status". */
static gchar *request_endpoint(const char *request, gsize length) {
    const char *line_end = g_strstr_len(request, (gssize)length, "\r\n");
    gchar *line = g_strndup(request, line_end ? (gsize)(line_end - request) : length);
    gchar **parts = g_strsplit(line, " ", 3);
    gchar *endpoint = NULL;

    if (parts[0] && parts[1]) {
        gchar *path = parts[1];
        path[strcspn(path, "?#")] = '\0';
        while (*path && path[strlen(path) - 1] == '/')
            path[strlen(path) - 1] = '\0';
        const char *slash = strrchr(path, '/');
        endpoint = g_strdup(slash ? slash + 1 : path);
    }
    g_strfreev(parts);
    g_free(line);
    return endpoint;
}

/* Answers and SSO results only make sense while the client waits for them. */
static const char *pass_to_waiting_client(const char *command, const char *body, gsize length) {
    if (client_pid <= 0 || !pending_login)
        return "no sign-in is waiting for input";
    if (memchr(body, '\n', length) || memchr(body, '\r', length))
        return "invalid input";
    gchar *text = g_strndup(body, length);
    gchar *line = g_strconcat(command, " ", text, NULL);
    write_client(line);
    memset(text, 0, strlen(text));
    memset(line, 0, strlen(line));
    g_free(text);
    g_free(line);
    return NULL;
}

static gboolean on_api_request(GSocketService *service, GSocketConnection *connection, GObject *source,
                               gpointer user_data) {
    (void)service;
    (void)source;
    (void)user_data;

    GInputStream *in = g_io_stream_get_input_stream(G_IO_STREAM(connection));
    GOutputStream *out = g_io_stream_get_output_stream(G_IO_STREAM(connection));
    GString *request = g_string_new(NULL);
    gchar buffer[8192];
    gsize header_length = 0, content_length = 0;
    gboolean too_large = FALSE;

    for (;;) {
        gssize got = g_input_stream_read(in, buffer, sizeof(buffer), NULL, NULL);
        if (got <= 0)
            break;
        g_string_append_len(request, buffer, got);
        if (request->len > MAX_REQUEST) {
            too_large = TRUE;
            break;
        }
        if (!header_length) {
            gchar *end = g_strstr_len(request->str, (gssize)request->len, "\r\n\r\n");
            if (!end)
                continue;
            header_length = (gsize)(end - request->str) + 4;
            content_length = header_content_length(request->str, header_length);
            if (content_length > MAX_REQUEST) {
                too_large = TRUE;
                break;
            }
        }
        if (request->len - header_length >= content_length)
            break;
    }

    if (too_large) {
        send_response(out, "413 Payload Too Large", "text/plain", "request too large\n");
    } else if (!header_length) {
        send_response(out, "400 Bad Request", "text/plain", "bad request\n");
    } else {
        gboolean is_get = g_str_has_prefix(request->str, "GET ");
        gboolean is_post = g_str_has_prefix(request->str, "POST ");
        gchar *endpoint = request_endpoint(request->str, header_length);
        const char *body = request->str + header_length;
        gsize body_length = MIN(request->len - header_length, content_length);

        if (is_get && g_strcmp0(endpoint, "settings") == 0) {
            gchar *json = settings_json();
            send_response(out, "200 OK", "application/json", json);
            g_free(json);
        } else if (is_post && g_strcmp0(endpoint, "settings") == 0) {
            gchar *form = g_strndup(body, body_length);
            gboolean changed = apply_settings_body(form);
            g_free(form);
            send_response(out, "200 OK", "application/json",
                          changed ? "{\"status\":\"ok\",\"changed\":true}" : "{\"status\":\"ok\",\"changed\":false}");
            if (changed)
                schedule_config_apply();
        } else if (is_get && g_strcmp0(endpoint, "status") == 0) {
            gchar *json = status_json();
            send_response(out, "200 OK", "application/json", json);
            g_free(json);
        } else if (is_post && g_strcmp0(endpoint, "cert") == 0) {
            const char *error = store_pem(CLIENT_CERT_FILE, body, body_length, "client certificate");
            send_result(out, error);
            if (!error)
                schedule_config_apply();
        } else if (is_post && g_strcmp0(endpoint, "ca") == 0) {
            const char *error = store_pem(CA_FILE, body, body_length, "CA certificate");
            send_result(out, error);
            if (!error)
                schedule_config_apply();
        } else if (is_post && g_strcmp0(endpoint, "reconnect") == 0) {
            send_result(out, NULL);
            syslog(LOG_INFO, "manual reconnect requested");
            restart_client(FALSE);
        } else if (is_post && g_strcmp0(endpoint, "login") == 0) {
            if (!param_is("Enabled", "yes") || !*param("Server")) {
                send_result(out, "enable the VPN and set the server first");
            } else {
                send_result(out, NULL);
                syslog(LOG_INFO, "interactive sign-in started from the settings page");
                restart_client(TRUE);
            }
        } else if (is_post && g_strcmp0(endpoint, "answer") == 0) {
            send_result(out, pass_to_waiting_client("answer", body, body_length));
        } else if (is_post && g_strcmp0(endpoint, "sso") == 0) {
            /* The pasted page or link may contain anything, so encode it. */
            gchar *text = g_strndup(body, body_length);
            gchar *escaped = g_uri_escape_string(text, NULL, FALSE);
            send_result(out, pass_to_waiting_client("sso", escaped, strlen(escaped)));
            memset(text, 0, strlen(text));
            g_free(text);
            g_free(escaped);
        } else if (is_post && g_strcmp0(endpoint, "cancel") == 0) {
            send_result(out, NULL);
            if (client_pid > 0 && pending_login)
                write_client("cancel");
        } else {
            send_response(out, "404 Not Found", "text/plain", "not found\n");
        }
        g_free(endpoint);
    }

    g_string_free(request, TRUE);
    g_io_stream_close(G_IO_STREAM(connection), NULL, NULL);
    return TRUE;
}

static gboolean start_api_server(void) {
    GError *error = NULL;
    GSocketService *service = g_socket_service_new();
    GInetAddress *address = g_inet_address_new_loopback(G_SOCKET_FAMILY_IPV4);
    GSocketAddress *socket_address = g_inet_socket_address_new(address, SETTINGS_HTTP_PORT);
    gboolean added = g_socket_listener_add_address(G_SOCKET_LISTENER(service), socket_address, G_SOCKET_TYPE_STREAM,
                                                   G_SOCKET_PROTOCOL_TCP, NULL, NULL, &error);

    g_object_unref(socket_address);
    g_object_unref(address);

    if (!added) {
        /* A failure here usually means another ACAP already claimed the port,
         * which would silently forward this app's API to that app. */
        syslog(LOG_ERR, "settings server cannot bind 127.0.0.1:%d: %s", SETTINGS_HTTP_PORT,
               error ? error->message : "unknown error");
        g_clear_error(&error);
        g_object_unref(service);
        return FALSE;
    }

    g_signal_connect(service, "incoming", G_CALLBACK(on_api_request), NULL);
    g_socket_service_start(service);
    syslog(LOG_INFO, "settings server listening on 127.0.0.1:%d", SETTINGS_HTTP_PORT);
    return TRUE;
}

/* ── main ────────────────────────────────────────────────────────────────── */

/* The main loop is about to stop, so reap the client here rather than in the
 * child watch. It detaches, keeping the gateway session for the next start. */
static void stop_client_blocking(void) {
    if (client_pid <= 0)
        return;
    kill(client_pid, SIGTERM);
    for (int i = 0; i < 50; i++) {
        if (waitpid(client_pid, NULL, WNOHANG) == client_pid) {
            client_pid = -1;
            break;
        }
        usleep(100000);
    }
    if (client_pid > 0) {
        kill(-client_pid, SIGKILL);
        kill(client_pid, SIGKILL);
        waitpid(client_pid, NULL, 0);
        client_pid = -1;
    }
    kill_stale_sidecar();
}

static gboolean on_terminate(gpointer user_data) {
    (void)user_data;
    syslog(LOG_INFO, "stopping");
    shutting_down = TRUE;
    g_main_loop_quit(main_loop);
    return G_SOURCE_REMOVE;
}

int main(void) {
    GError *error = NULL;

    openlog(APP_NAME, LOG_PID, LOG_USER);
    signal(SIGPIPE, SIG_IGN);
    g_mkdir_with_parents(STATE_DIR, 0755);

    parameter_handle = ax_parameter_new(APP_NAME, &error);
    if (!parameter_handle) {
        syslog(LOG_ERR, "ax_parameter_new failed: %s", error ? error->message : "unknown error");
        g_clear_error(&error);
        return EXIT_FAILURE;
    }

    for (gsize i = 0; i < G_N_ELEMENTS(parameters); i++) {
        load_parameter(&parameters[i]);
        if (!ax_parameter_register_callback(parameter_handle, parameters[i].name, on_parameter_changed, NULL, &error)) {
            syslog(LOG_WARNING, "callback for %s failed: %s", parameters[i].name,
                   error ? error->message : "unknown error");
        }
        g_clear_error(&error);
    }
    load_device_info();
    applied_session_key = session_key();

    main_loop = g_main_loop_new(NULL, FALSE);
    g_unix_signal_add(SIGTERM, on_terminate, NULL);
    g_unix_signal_add(SIGINT, on_terminate, NULL);

    start_api_server();
    start_client(FALSE);

    syslog(LOG_INFO, "%s started", APP_NAME);
    g_main_loop_run(main_loop);

    stop_client_blocking();
    for (gsize i = 0; i < G_N_ELEMENTS(parameters); i++)
        g_free(parameters[i].value);
    ax_parameter_free(parameter_handle);
    g_main_loop_unref(main_loop);
    closelog();
    return EXIT_SUCCESS;
}
