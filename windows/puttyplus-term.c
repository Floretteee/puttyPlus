#include <stdio.h>
#include <stdlib.h>

#include "putty.h"
#include "ssh.h"
#include "storage.h"
#include "wsseat.h"

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

    CmdlineArgList *arglist = cmdline_arg_list_from_GetCommandLineW();
    size_t arglistpos = 0;
    while (arglist->args[arglistpos]) {
        CmdlineArg *arg = arglist->args[arglistpos++];
        CmdlineArg *nextarg = arglist->args[arglistpos];
        const char *p = cmdline_arg_to_str(arg);
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

    if (!cmdline_host_ok(conf)) {
        fprintf(stderr, "puttyplus-term: no valid host name provided\n"
                "try \"puttyplus-term --help\" for help\n");
        cmdline_arg_list_free(arglist);
        return 1;
    }

    prepare_session(conf);
    cmdline_run_saved(conf);

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
