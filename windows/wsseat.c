#include "putty.h"
#include "ssh.h"
#include "storage.h"
#include "tree234.h"

#include "wsseat.h"

#ifndef ENABLE_VIRTUAL_TERMINAL_INPUT
#define ENABLE_VIRTUAL_TERMINAL_INPUT 0x0200
#endif
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#ifndef DISABLE_NEWLINE_AUTO_RETURN
#define DISABLE_NEWLINE_AUTO_RETURN 0x0008
#endif

static void ws_seat_echoedit_update(Seat *seat, bool echo, bool edit)
{
    WsSeat *ws = container_of(seat, WsSeat, seat);
    DWORD mode = ENABLE_PROCESSED_INPUT;
    if (echo)
        mode |= ENABLE_ECHO_INPUT;
    if (edit) {
        mode |= ENABLE_LINE_INPUT;
    } else {
        mode |= ENABLE_VIRTUAL_TERMINAL_INPUT;
        mode &= ~ENABLE_PROCESSED_INPUT;
    }
    if (!SetConsoleMode(ws->inhandle, mode) && (mode & ENABLE_VIRTUAL_TERMINAL_INPUT)) {
        mode &= ~ENABLE_VIRTUAL_TERMINAL_INPUT;
        SetConsoleMode(ws->inhandle, mode);
    }
}

static size_t ws_seat_output(
    Seat *seat, SeatOutputType type, const void *data, size_t len)
{
    WsSeat *ws = container_of(seat, WsSeat, seat);
    bool is_stderr = type != SEAT_OUTPUT_STDOUT;
    BinarySink *bs = is_stderr ? ws->stderr_bs : ws->stdout_bs;
    put_data(bs, data, len);
    return handle_backlog(ws->stdout_handle) + handle_backlog(ws->stderr_handle);
}

static bool ws_seat_eof(Seat *seat)
{
    WsSeat *ws = container_of(seat, WsSeat, seat);
    handle_write_eof(ws->stdout_handle);
    return false;
}

static SeatPromptResult ws_seat_get_userpass_input(Seat *seat, prompts_t *p)
{
    WsSeat *ws = container_of(seat, WsSeat, seat);
    SeatPromptResult spr;
    spr = cmdline_get_passwd_input(p, &ws->cmdline_state, false);
    if (spr.kind == SPRK_INCOMPLETE)
        spr = console_get_userpass_input(p);
    return spr;
}

static bool ws_seat_interactive(Seat *seat)
{
    WsSeat *ws = container_of(seat, WsSeat, seat);
    return (!*conf_get_str_ambi(ws->conf, CONF_remote_cmd, NULL) &&
            !*conf_get_str_ambi(ws->conf, CONF_remote_cmd2, NULL) &&
            !*conf_get_str(ws->conf, CONF_ssh_nc_host));
}

const SeatVtable ws_seat_vt = {
    .output = ws_seat_output,
    .eof = ws_seat_eof,
    .sent = nullseat_sent,
    .banner = nullseat_banner_to_stderr,
    .get_userpass_input = ws_seat_get_userpass_input,
    .notify_session_started = nullseat_notify_session_started,
    .notify_remote_exit = nullseat_notify_remote_exit,
    .notify_remote_disconnect = nullseat_notify_remote_disconnect,
    .connection_fatal = console_connection_fatal,
    .nonfatal = console_nonfatal,
    .update_specials_menu = nullseat_update_specials_menu,
    .get_ttymode = nullseat_get_ttymode,
    .set_busy_status = nullseat_set_busy_status,
    .confirm_ssh_host_key = console_confirm_ssh_host_key,
    .confirm_weak_crypto_primitive = console_confirm_weak_crypto_primitive,
    .confirm_weak_cached_hostkey = console_confirm_weak_cached_hostkey,
    .prompt_descriptions = console_prompt_descriptions,
    .is_utf8 = nullseat_is_never_utf8,
    .echoedit_update = ws_seat_echoedit_update,
    .get_display = nullseat_get_display,
    .get_windowid = nullseat_get_windowid,
    .get_window_pixel_size = nullseat_get_window_pixel_size,
    .stripctrl_new = console_stripctrl_new,
    .set_trust_status = console_set_trust_status,
    .can_set_trust_status = console_can_set_trust_status,
    .has_mixed_input_stream = console_has_mixed_input_stream,
    .verbose = nullseat_verbose_yes,
    .interactive = ws_seat_interactive,
    .get_cursor_position = nullseat_get_cursor_position,
};

static size_t ws_seat_stdin_gotdata(
    struct handle *h, const void *data, size_t len, int err)
{
    WsSeat *ws = (WsSeat *)handle_get_privdata(h);
    if (err) {
        cleanup_exit(0);
    }
    if (backend_connected(ws->backend)) {
        if (len > 0) {
            backend_send(ws->backend, data, len);
            return backend_sendbuffer(ws->backend);
        } else {
            backend_special(ws->backend, SS_EOF, 0);
            return 0;
        }
    }
    return 0;
}

static void ws_seat_stdouterr_sent(
    struct handle *h, size_t new_backlog, int err, bool close)
{
    WsSeat *ws = (WsSeat *)handle_get_privdata(h);
    if (close) {
        if (h == ws->stdout_handle)
            CloseHandle(ws->outhandle);
        else
            CloseHandle(ws->errhandle);
    }
    if (err) {
        cleanup_exit(0);
    }
    if (backend_connected(ws->backend)) {
        backend_unthrottle(ws->backend, (handle_backlog(ws->stdout_handle) +
                                         handle_backlog(ws->stderr_handle)));
    }
}

WsSeat *ws_seat_new(Conf *conf, LogContext *logctx)
{
    WsSeat *ws = snew(WsSeat);
    memset(ws, 0, sizeof(*ws));
    ws->seat.vt = &ws_seat_vt;
    ws->conf = conf;
    ws->logctx = logctx;
    memset(&ws->cmdline_state, 0, sizeof(ws->cmdline_state));
    return ws;
}

void ws_seat_free(WsSeat *ws)
{
    if (ws->stdout_handle) handle_free(ws->stdout_handle);
    if (ws->stderr_handle) handle_free(ws->stderr_handle);
    if (ws->stdin_handle) handle_free(ws->stdin_handle);
    sfree(ws);
}

void ws_seat_start_backend(WsSeat *ws)
{
    const struct BackendVtable *vt;
    char *error, *realhost;
    bool nodelay;

    ws->inhandle = GetStdHandle(STD_INPUT_HANDLE);
    ws->outhandle = GetStdHandle(STD_OUTPUT_HANDLE);
    ws->errhandle = GetStdHandle(STD_ERROR_HANDLE);

    {
        DWORD outmode = 0;
        if (GetConsoleMode(ws->outhandle, &outmode))
            SetConsoleMode(ws->outhandle,
                           outmode | ENABLE_VIRTUAL_TERMINAL_PROCESSING |
                           DISABLE_NEWLINE_AUTO_RETURN);
        if (GetConsoleMode(ws->errhandle, &outmode))
            SetConsoleMode(ws->errhandle,
                           outmode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }

    GetConsoleMode(ws->inhandle, &ws->orig_console_mode);
    SetConsoleMode(ws->inhandle,
                   ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT |
                   ENABLE_ECHO_INPUT);

    ws->stdout_handle = handle_output_new(
        ws->outhandle, ws_seat_stdouterr_sent, ws, 0);
    ws->stderr_handle = handle_output_new(
        ws->errhandle, ws_seat_stdouterr_sent, ws, 0);
    handle_sink_init(&ws->stdout_hs, ws->stdout_handle);
    handle_sink_init(&ws->stderr_hs, ws->stderr_handle);
    ws->stdout_bs = BinarySink_UPCAST(&ws->stdout_hs);
    ws->stderr_bs = BinarySink_UPCAST(&ws->stderr_hs);

    vt = backend_vt_from_proto(conf_get_int(ws->conf, CONF_protocol));
    if (!vt) {
        fprintf(stderr, "Internal fault: Unsupported protocol found\n");
        cleanup_exit(1);
    }

    nodelay = conf_get_bool(ws->conf, CONF_tcp_nodelay) &&
        (GetFileType(ws->inhandle) == FILE_TYPE_CHAR);

    error = backend_init(vt, &ws->seat, &ws->backend, ws->logctx, ws->conf,
                         conf_get_str(ws->conf, CONF_host),
                         conf_get_int(ws->conf, CONF_port),
                         &realhost, nodelay,
                         conf_get_bool(ws->conf, CONF_tcp_keepalives));
    if (error) {
        fprintf(stderr, "Unable to open connection:\n%s", error);
        sfree(error);
        cleanup_exit(1);
    }
    ldisc_create(ws->conf, NULL, ws->backend, &ws->seat);
    sfree(realhost);
    ws->sending = false;
}

static bool ws_seat_mainloop_pre(void *vctx, const HANDLE **extra_handles,
                                 size_t *n_extra_handles)
{
    WsSeat *ws = (WsSeat *)vctx;
    if (!ws->sending && backend_sendok(ws->backend)) {
        ws->stdin_handle = handle_input_new(ws->inhandle, ws_seat_stdin_gotdata,
                                            ws, 0);
        ws->sending = true;
    }
    return true;
}

static bool ws_seat_mainloop_post(void *vctx, size_t extra_handle_index)
{
    WsSeat *ws = (WsSeat *)vctx;
    if (ws->sending)
        handle_unthrottle(ws->stdin_handle, backend_sendbuffer(ws->backend));
    if (!backend_connected(ws->backend) &&
        handle_backlog(ws->stdout_handle) + handle_backlog(ws->stderr_handle) == 0)
        return false;
    return true;
}

int ws_seat_run_main_loop(WsSeat *ws)
{
    cli_main_loop(ws_seat_mainloop_pre, ws_seat_mainloop_post, ws);
    int exitcode = backend_exitcode(ws->backend);
    if (exitcode < 0) {
        fprintf(stderr, "Remote process exit code unavailable\n");
        exitcode = 1;
    }
    return exitcode;
}

void ws_seat_cleanup(WsSeat *ws)
{
    if (ws->stdout_scc) stripctrl_free(ws->stdout_scc);
    if (ws->stderr_scc) stripctrl_free(ws->stderr_scc);
    SetConsoleMode(ws->inhandle, ws->orig_console_mode);
    ws_seat_free(ws);
}
