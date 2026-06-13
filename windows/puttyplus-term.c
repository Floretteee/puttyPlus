#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#include "putty.h"
#include <shellapi.h>
#include "ssh.h"
#include "storage.h"
#include "wsseat.h"

static wchar_t *puttyplus_quote_wide_arg(const wchar_t *arg)
{
    wchar_t *ret = snewn(wcslen(arg) * 2 + 3, wchar_t);
    wchar_t *out = ret;
    int backslashes = 0;

    *out++ = L'"';
    while (*arg) {
        if (*arg == L'\\') {
            backslashes++;
        } else if (*arg == L'"') {
            while (backslashes-- > 0)
                *out++ = L'\\';
            *out++ = L'\\';
            *out++ = L'"';
            backslashes = 0;
        } else {
            while (backslashes-- > 0)
                *out++ = L'\\';
            *out++ = *arg;
            backslashes = 0;
        }
        arg++;
    }
    while (backslashes-- > 0) {
        *out++ = L'\\';
        *out++ = L'\\';
    }
    *out++ = L'"';
    *out = L'\0';
    return ret;
}

static bool puttyplus_running_in_windows_terminal(void)
{
    wchar_t buf[2];
    return GetEnvironmentVariableW(L"WT_SESSION", buf, lenof(buf)) > 0;
}

static bool puttyplus_command_has_no_wt_flag(CmdlineArgList *arglist)
{
    for (size_t i = 0; arglist->args[i]; i++) {
        const char *p = cmdline_arg_to_str(arglist->args[i]);
        if (!strcmp(p, "--puttyplus-no-wt"))
            return true;
    }
    return false;
}

static bool puttyplus_relaunch_self_in_windows_terminal(CmdlineArgList *arglist)
{
    wchar_t module[MAX_PATH];
    wchar_t *qmodule, *params;
    size_t params_len = 96;
    HINSTANCE result;

    if (!arglist->args[0] ||
        puttyplus_running_in_windows_terminal() ||
        puttyplus_command_has_no_wt_flag(arglist))
        return false;

    if (!GetModuleFileNameW(NULL, module, lenof(module)))
        return false;
    module[lenof(module) - 1] = L'\0';

    qmodule = puttyplus_quote_wide_arg(module);
    params_len += wcslen(qmodule);
    for (size_t i = 0; arglist->args[i]; i++) {
        Filename *fn = cmdline_arg_to_filename(arglist->args[i]);
        wchar_t *qarg = puttyplus_quote_wide_arg(filename_to_wstr(fn));
        params_len += wcslen(qarg) + 1;
        sfree(qarg);
        filename_free(fn);
    }

    params = snewn(params_len, wchar_t);
    swprintf(params, params_len,
             L"new-tab --title PuTTYPlus -- %ls --puttyplus-no-wt",
             qmodule);

    for (size_t i = 0; arglist->args[i]; i++) {
        Filename *fn = cmdline_arg_to_filename(arglist->args[i]);
        wchar_t *qarg = puttyplus_quote_wide_arg(filename_to_wstr(fn));
        wcscat(params, L" ");
        wcscat(params, qarg);
        sfree(qarg);
        filename_free(fn);
    }

    result = ShellExecuteW(NULL, L"open", L"wt.exe", params,
                           NULL, SW_SHOWNORMAL);

    sfree(params);
    sfree(qmodule);
    return (INT_PTR)result > 32;
}

static bool puttyplus_load_conf_file(Conf *conf, CmdlineArg *arg)
{
    Filename *fn = cmdline_arg_to_filename(arg);
    FILE *fp = f_open(fn, "rb", false);
    strbuf *buf;
    bool ok = false;

    if (!fp) {
        filename_free(fn);
        return false;
    }

    buf = strbuf_new();
    while (true) {
        char tmp[4096];
        size_t ret = fread(tmp, 1, sizeof(tmp), fp);
        if (ret > 0)
            put_data(buf, tmp, ret);
        if (ret < sizeof(tmp))
            break;
    }

    if (!ferror(fp) && buf->len > 0) {
        BinarySource src[1];
        BinarySource_BARE_INIT(src, buf->s, buf->len);
        ok = conf_deserialise(conf, src);
    }
    fclose(fp);

    DeleteFileW(filename_to_wstr(fn));
    filename_free(fn);
    strbuf_free(buf);
    return ok;
}

const unsigned cmdline_tooltype =
    TOOLTYPE_HOST_ARG |
    TOOLTYPE_HOST_ARG_CAN_BE_SESSION |
    TOOLTYPE_HOST_ARG_PROTOCOL_PREFIX |
    TOOLTYPE_HOST_ARG_FROM_LAUNCHABLE_LOAD;

const bool share_can_be_downstream = true;
const bool share_can_be_upstream = true;

void cmdline_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    console_print_error_msg_fmt_v("puttyplus-term", fmt, ap);
    va_end(ap);
    exit(1);
}

static void version(void)
{
    char *buildinfo_text = buildinfo("\n");
    printf("puttyplus-term: %s\n%s\n", ver, buildinfo_text);
    sfree(buildinfo_text);
    exit(0);
}

static void usage(void)
{
    printf("PuTTYPlus-Term: WebSocket SSH client for Windows Terminal\n");
    printf("%s\n", ver);
    printf("Usage: puttyplus-term [options] [user@]host\n");
    printf("       (\"host\" can also be a PuTTY saved session name)\n");
    printf("  -V        print version information\n");
    printf("  -load sessname  Load settings from saved session\n");
    printf("  -v        show verbose messages\n");
    printf("  -l user   connect with specified username\n");
    printf("  -P port   connect to specified port\n");
    printf("  -batch    disable all interactive prompts\n");
    printf("  -pwfile file   login with password read from file\n");
    printf("  -C        enable compression\n");
    printf("  -hostkey keyid  manually specify a host key\n");
    exit(0);
}

int main(int argc, char **argv)
{
    Conf *conf;
    LogContext *logctx;
    WsSeat *ws;
    int exitcode;
    bool errors;
    bool loaded_conf_file;

    dll_hijacking_protection();
    enable_dit();

    settings_set_default_protocol(PROT_SSH);
    settings_set_default_port(22);

    conf = conf_new();
    do_defaults(NULL, conf);
    settings_set_default_protocol(conf_get_int(conf, CONF_protocol));
    settings_set_default_port(conf_get_int(conf, CONF_port));
    conf_set_bool(conf, CONF_ws_proxy_enable, true);
    errors = false;
    loaded_conf_file = false;

    CmdlineArgList *arglist = cmdline_arg_list_from_GetCommandLineW();
    if (puttyplus_relaunch_self_in_windows_terminal(arglist)) {
        cmdline_arg_list_free(arglist);
        return 0;
    }

    size_t arglistpos = 0;
    while (arglist->args[arglistpos]) {
        CmdlineArg *arg = arglist->args[arglistpos++];
        CmdlineArg *nextarg = arglist->args[arglistpos];
        const char *p = cmdline_arg_to_str(arg);
        if (!strcmp(p, "--puttyplus-no-wt")) {
            continue;
        } else if (!strcmp(p, "--puttyplus-conf")) {
            if (!nextarg) {
                fprintf(stderr,
                        "puttyplus-term: option \"%s\" requires an argument\n",
                        p);
                errors = true;
            } else if (!puttyplus_load_conf_file(conf, nextarg)) {
                fprintf(stderr,
                        "puttyplus-term: could not load configuration file\n");
                errors = true;
            } else {
                loaded_conf_file = true;
                arglistpos++;
            }
            continue;
        }
        int ret = cmdline_process_param(arg, nextarg, 1, conf);
        if (ret == -2) {
            fprintf(stderr,
                    "puttyplus-term: option \"%s\" requires an argument\n", p);
            errors = true;
        } else if (ret == 2) {
            arglistpos++;
        } else if (ret == 1) {
            continue;
        } else if (!strcmp(p, "-V") || !strcmp(p, "--version")) {
            version();
        } else if (!strcmp(p, "--help")) {
            usage();
            exit(0);
        } else if (!strcmp(p, "-pgpfp")) {
            pgp_fingerprints();
            exit(0);
        } else if (!strcmp(p, "-no-antispoof")) {
            console_antispoof_prompt = false;
        } else if (*p != '-') {
            strbuf *cmdbuf = strbuf_new();
            while (arg) {
                if (cmdbuf->len > 0)
                    put_byte(cmdbuf, ' ');
                put_dataz(cmdbuf, cmdline_arg_to_utf8(arg));
                arg = arglist->args[arglistpos++];
            }
            conf_set_str(conf, CONF_remote_cmd, cmdbuf->s);
            conf_set_str(conf, CONF_remote_cmd2, "");
            conf_set_bool(conf, CONF_nopty, true);
            strbuf_free(cmdbuf);
            break;
        } else {
            fprintf(stderr, "puttyplus-term: unknown option \"%s\"\n", p);
            errors = true;
        }
    }

    if (errors)
        return 1;

    if (!(loaded_conf_file ? conf_launchable(conf) : cmdline_host_ok(conf))) {
        fprintf(stderr, "puttyplus-term: no valid host name provided\n"
                "try \"puttyplus-term --help\" for help\n");
        cmdline_arg_list_free(arglist);
        return 1;
    }

    prepare_session(conf);
    if (!loaded_conf_file)
        cmdline_run_saved(conf);
    conf_set_bool(conf, CONF_ws_proxy_enable, true);

    if (conf_get_int(conf, CONF_protocol) == PROT_SSH &&
        !conf_get_bool(conf, CONF_x11_forward) &&
        !conf_get_bool(conf, CONF_agentfwd) &&
        !conf_get_str_nthstrkey(conf, CONF_portfwd, 0))
        conf_set_bool(conf, CONF_ssh_simple, true);

    sk_init();
    if (p_WSAEventSelect == NULL) {
        fprintf(stderr, "puttyplus-term requires WinSock 2\n");
        return 1;
    }

    logctx = log_init(console_cli_logpolicy, conf);

    SetConsoleTitle("PuTTYPlus");

    ws = ws_seat_new(conf, logctx);
    ws_seat_start_backend(ws);
    exitcode = ws_seat_run_main_loop(ws);
    ws_seat_cleanup(ws);
    cleanup_exit(exitcode);
    return 0;
}
