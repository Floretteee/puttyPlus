#ifndef PUTTY_WS_SEAT_H
#define PUTTY_WS_SEAT_H

typedef struct WsSeat {
    Seat seat;
    Backend *backend;
    LogContext *logctx;
    Conf *conf;
    HANDLE inhandle, outhandle, errhandle;
    struct handle *stdin_handle, *stdout_handle, *stderr_handle;
    handle_sink stdout_hs, stderr_hs;
    StripCtrlChars *stdout_scc, *stderr_scc;
    BinarySink *stdout_bs, *stderr_bs;
    DWORD orig_console_mode;
    bool sending;
    cmdline_get_passwd_input_state cmdline_state;
} WsSeat;

extern const SeatVtable ws_seat_vt;

WsSeat *ws_seat_new(Conf *conf, LogContext *logctx);
void ws_seat_free(WsSeat *ws);
void ws_seat_start_backend(WsSeat *ws);
int ws_seat_run_main_loop(WsSeat *ws);
void ws_seat_cleanup(WsSeat *ws);

#endif
