#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "putty.h"
#include "network.h"

struct WSSocket {
    const struct SocketVtable *vt;
    const char *error;
    Plug *plug;

    char *proxy_host;
    int proxy_port;
    char *proxy_path;
    bool use_tls;
    char *target_host;
    int target_port;

    SOCKET s;
    HANDLE thread;
    CRITICAL_SECTION lock;

    bufchain send_queue;
    bool closing;
    bool closed;

    bufchain recv_queue;
    struct IdempotentCallback recv_ic;
    bool recv_queued;

    char *pending_error;
    struct IdempotentCallback error_ic;
    bool error_queued;

    bool connected;
    struct IdempotentCallback connect_ic;
    bool connect_queued;

    bool frozen;
};

static void wsnet_recv_idempotent(void *ctx);
static void wsnet_error_idempotent(void *ctx);
static void wsnet_connect_idempotent(void *ctx);

static const char *wsnet_socket_error(Socket *s)
{
    struct WSSocket *ws = container_of(s, struct WSSocket, vt);
    return ws->error ? ws->error : "";
}

static Plug *wsnet_plug(Socket *s, Plug *p)
{
    struct WSSocket *ws = container_of(s, struct WSSocket, vt);
    Plug *old = ws->plug;
    if (p) ws->plug = p;
    return old;
}

static void wsnet_queue_recv(struct WSSocket *ws)
{
    if (!ws->recv_queued) {
        ws->recv_queued = true;
        queue_idempotent_callback(&ws->recv_ic);
    }
}

static void wsnet_queue_error(struct WSSocket *ws)
{
    if (!ws->error_queued) {
        ws->error_queued = true;
        queue_idempotent_callback(&ws->error_ic);
    }
}

static void wsnet_queue_connect(struct WSSocket *ws)
{
    if (!ws->connect_queued) {
        ws->connect_queued = true;
        queue_idempotent_callback(&ws->connect_ic);
    }
}

static void wsnet_send_websocket_frame(SOCKET s, const unsigned char *data,
                                        size_t len, int opcode)
{
    unsigned char header[14];
    size_t hdr_len = 0;

    header[hdr_len++] = 0x80 | opcode;

    unsigned char mask[4];
    for (int i = 0; i < 4; i++)
        mask[i] = (rand() & 0xFF);

    if (len < 126) {
        header[hdr_len++] = 0x80 | (unsigned char)len;
    } else if (len < 65536) {
        header[hdr_len++] = 0x80 | 126;
        header[hdr_len++] = (len >> 8) & 0xFF;
        header[hdr_len++] = len & 0xFF;
    } else {
        header[hdr_len++] = 0x80 | 127;
        uint64_t n = len;
        for (int i = 7; i >= 0; i--)
            header[hdr_len++] = (n >> (i * 8)) & 0xFF;
    }

    for (int i = 0; i < 4; i++)
        header[hdr_len++] = mask[i];

    send(s, (const char *)header, hdr_len, 0);

    unsigned char *masked = (unsigned char *)malloc(len);
    for (size_t i = 0; i < len; i++)
        masked[i] = data[i] ^ mask[i & 3];
    send(s, (const char *)masked, len, 0);
    free(masked);
}

static void wsnet_generate_key(char *key_b64)
{
    unsigned char key_bytes[16];
    for (int i = 0; i < 16; i++)
        key_bytes[i] = rand() & 0xFF;

    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int val = 0, bits = 0, out = 0;
    for (int i = 0; i < 16; i++) {
        val = (val << 8) | key_bytes[i];
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            key_b64[out++] = b64[(val >> bits) & 0x3F];
        }
    }
    if (bits > 0)
        key_b64[out++] = b64[(val << (6 - bits)) & 0x3F];
    while (out % 4)
        key_b64[out++] = '=';
    key_b64[out] = '\0';
}

static DWORD WINAPI wsnet_thread(LPVOID param)
{
    struct WSSocket *ws = (struct WSSocket *)param;

    struct addrinfo hints, *ai;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    sprintf(port_str, "%d", ws->proxy_port);

    if (getaddrinfo(ws->proxy_host, port_str, &hints, &ai) != 0) {
        ws->pending_error = "WebSocket: DNS resolution failed";
        wsnet_queue_error(ws);
        return 1;
    }

    ws->s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (ws->s == INVALID_SOCKET) {
        ws->pending_error = "WebSocket: socket creation failed";
        freeaddrinfo(ai);
        wsnet_queue_error(ws);
        return 1;
    }

    u_long nonblock = 0;
    ioctlsocket(ws->s, FIONBIO, &nonblock);

    if (connect(ws->s, ai->ai_addr, (int)ai->ai_addrlen) == SOCKET_ERROR &&
        WSAGetLastError() != WSAEWOULDBLOCK) {
        ws->pending_error = "WebSocket: connect failed";
        freeaddrinfo(ai);
        closesocket(ws->s);
        ws->s = INVALID_SOCKET;
        wsnet_queue_error(ws);
        return 1;
    }

    fd_set wset, eset;
    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    FD_ZERO(&wset);
    FD_SET(ws->s, &wset);
    FD_ZERO(&eset);
    FD_SET(ws->s, &eset);

    if (select(0, NULL, &wset, &eset, &tv) <= 0) {
        ws->pending_error = "WebSocket: connection timeout";
        freeaddrinfo(ai);
        closesocket(ws->s);
        ws->s = INVALID_SOCKET;
        wsnet_queue_error(ws);
        return 1;
    }

    freeaddrinfo(ai);

    char key_b64[64];
    wsnet_generate_key(key_b64);

    const char *path = ws->proxy_path ? ws->proxy_path : "/p";

    char handshake[1024];
    int hlen = sprintf(handshake,
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n",
        path, ws->proxy_host, ws->proxy_port, key_b64);

    if (send(ws->s, handshake, hlen, 0) != hlen) {
        ws->pending_error = "WebSocket: handshake send failed";
        closesocket(ws->s);
        ws->s = INVALID_SOCKET;
        wsnet_queue_error(ws);
        return 1;
    }

    char resp[4096];
    int total = 0;
    bool got_headers = false;
    while (!got_headers) {
        int ret = recv(ws->s, resp + total, sizeof(resp) - 1 - total, 0);
        if (ret <= 0) {
            ws->pending_error = "WebSocket: handshake failed";
            closesocket(ws->s);
            ws->s = INVALID_SOCKET;
            wsnet_queue_error(ws);
            return 1;
        }
        total += ret;
        resp[total] = '\0';

        if (strstr(resp, "\r\n\r\n")) {
            got_headers = true;
        }
    }

    int status;
    if (sscanf(resp, "HTTP/1.1 %d", &status) != 1 || status != 101) {
        ws->pending_error = "WebSocket: server rejected upgrade";
        closesocket(ws->s);
        ws->s = INVALID_SOCKET;
        wsnet_queue_error(ws);
        return 1;
    }

    ws->connected = true;
    wsnet_queue_connect(ws);

    char init_msg[256];
    int init_len = sprintf(init_msg,
        "{\"host\":\"%s\",\"port\":%d}",
        ws->target_host, ws->target_port);
    wsnet_send_websocket_frame(ws->s,
        (const unsigned char *)init_msg, init_len, 0x1);

    unsigned char frame_buf[65536];
    size_t frame_pos = 0;
    bool expecting_json = true;
    int json_len = 0;
    char json_buf[4096];

    while (!ws->closing) {
        EnterCriticalSection(&ws->lock);
        size_t send_len = bufchain_size(&ws->send_queue);
        if (send_len > 0) {
            ptrlen data = bufchain_prefix(&ws->send_queue);
            wsnet_send_websocket_frame(ws->s,
                (const unsigned char *)data.ptr, data.len, 0x2);
            bufchain_consume(&ws->send_queue, data.len);
        }
        LeaveCriticalSection(&ws->lock);

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ws->s, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        int sel = select(0, &rfds, NULL, NULL, &tv);

        if (sel > 0 && FD_ISSET(ws->s, &rfds)) {
            int ret = recv(ws->s, (char *)frame_buf + frame_pos,
                           (int)(sizeof(frame_buf) - frame_pos), 0);
            if (ret <= 0) {
                ws->pending_error = "WebSocket: connection lost";
                wsnet_queue_error(ws);
                break;
            }

            frame_pos += ret;
            size_t consumed = 0;

            while (consumed < frame_pos) {
                if (frame_pos - consumed < 2) break;

                unsigned char *f = frame_buf + consumed;
                int opcode = f[0] & 0x0F;
                bool masked = (f[1] & 0x80) != 0;
                size_t payload_len = f[1] & 0x7F;
                size_t hdr = 2;

                if (payload_len == 126) {
                    if (frame_pos - consumed < 4) break;
                    payload_len = (f[2] << 8) | f[3];
                    hdr = 4;
                } else if (payload_len == 127) {
                    if (frame_pos - consumed < 10) break;
                    payload_len = 0;
                    for (int i = 0; i < 8; i++)
                        payload_len = (payload_len << 8) | f[2 + i];
                    hdr = 10;
                }

                int mask_len = masked ? 4 : 0;
                if (frame_pos - consumed < hdr + mask_len + payload_len)
                    break;

                unsigned char *payload = f + hdr;
                if (masked) {
                    for (size_t i = 0; i < payload_len; i++)
                        payload[i] ^= payload[-4 + (i & 3)];
                    hdr += 4;
                    payload = f + hdr;
                }

                if (opcode == 0x8) {
                    ws->closing = true;
                    break;
                }

                if (opcode == 0x9) {
                    unsigned char pong[2] = {0x8A, 0x00};
                    send(ws->s, (const char *)pong, 2, 0);
                    consumed += hdr + payload_len;
                    continue;
                }

                if (opcode == 0x2 || opcode == 0x1) {
                    if (expecting_json) {
                        int copy = payload_len < (int)sizeof(json_buf) - 1
                                   ? (int)payload_len : (int)sizeof(json_buf) - 1;
                        memcpy(json_buf, payload, copy);
                        json_buf[copy] = '\0';
                        json_len = copy;
                        expecting_json = false;
                    } else {
                        EnterCriticalSection(&ws->lock);
                        bufchain_add(&ws->recv_queue,
                                     (const char *)payload, payload_len);
                        LeaveCriticalSection(&ws->lock);
                        wsnet_queue_recv(ws);
                    }
                }

                consumed += hdr + payload_len;
            }

            if (consumed > 0) {
                memmove(frame_buf, frame_buf + consumed,
                        frame_pos - consumed);
                frame_pos -= consumed;
            }

            if (json_len > 0) {
                char *status_str = strstr(json_buf, "\"status\"");
                char *ok_str = strstr(json_buf, "\"ok\"");
                if (status_str && !ok_str) {
                    ws->pending_error = "WebSocket: proxy rejected connection";
                    wsnet_queue_error(ws);
                    break;
                }
                json_len = 0;
                expecting_json = true;
            }
        }
    }

    if (ws->s != INVALID_SOCKET) {
        closesocket(ws->s);
        ws->s = INVALID_SOCKET;
    }

    EnterCriticalSection(&ws->lock);
    ws->closed = true;
    LeaveCriticalSection(&ws->lock);

    return 0;
}

static void wsnet_recv_idempotent(void *ctx)
{
    struct WSSocket *ws = (struct WSSocket *)ctx;
    ws->recv_queued = false;

    EnterCriticalSection(&ws->lock);
    while (bufchain_size(&ws->recv_queue) > 0) {
        ptrlen data = bufchain_prefix(&ws->recv_queue);
        if (!ws->frozen) {
            LeaveCriticalSection(&ws->lock);
            plug_receive(ws->plug, 0, data.ptr, data.len);
            EnterCriticalSection(&ws->lock);
        }
        bufchain_consume(&ws->recv_queue, data.len);
    }
    LeaveCriticalSection(&ws->lock);
}

static void wsnet_error_idempotent(void *ctx)
{
    struct WSSocket *ws = (struct WSSocket *)ctx;
    ws->error_queued = false;
    const char *err = ws->pending_error ? ws->pending_error : "unknown error";
    plug_closing(ws->plug, PLUGCLOSE_ERROR, err);
}

static void wsnet_connect_idempotent(void *ctx)
{
    struct WSSocket *ws = (struct WSSocket *)ctx;
    ws->connect_queued = false;
    plug_log(ws->plug, (Socket *)ws, PLUGLOG_CONNECT_SUCCESS, NULL, 0, NULL, 0);
}

static void wsnet_close(Socket *s)
{
    struct WSSocket *ws = container_of(s, struct WSSocket, vt);
    ws->closing = true;

    if (ws->s != INVALID_SOCKET) {
        closesocket(ws->s);
        ws->s = INVALID_SOCKET;
    }

    if (ws->thread) {
        WaitForSingleObject(ws->thread, 5000);
        CloseHandle(ws->thread);
    }

    DeleteCriticalSection(&ws->lock);
    bufchain_clear(&ws->send_queue);
    bufchain_clear(&ws->recv_queue);

    if (ws->proxy_host) sfree(ws->proxy_host);
    if (ws->proxy_path) sfree(ws->proxy_path);
    if (ws->target_host) sfree(ws->target_host);
    sfree(ws);
}

static size_t wsnet_write(Socket *s, const void *data, size_t len)
{
    struct WSSocket *ws = container_of(s, struct WSSocket, vt);

    EnterCriticalSection(&ws->lock);
    bufchain_add(&ws->send_queue, data, len);
    size_t backlog = bufchain_size(&ws->send_queue);
    LeaveCriticalSection(&ws->lock);

    return backlog;
}

static size_t wsnet_write_oob(Socket *s, const void *data, size_t len)
{
    return 0;
}

static void wsnet_write_eof(Socket *s)
{
    struct WSSocket *ws = container_of(s, struct WSSocket, vt);
    ws->closing = true;
    if (ws->s != INVALID_SOCKET) {
        unsigned char close_frame[2] = {0x88, 0x80};
        unsigned char mask[4] = {0};
        send(ws->s, (const char *)close_frame, 2, 0);
    }
}

static void wsnet_set_frozen(Socket *s, bool is_frozen)
{
    struct WSSocket *ws = container_of(s, struct WSSocket, vt);
    ws->frozen = is_frozen;
}

static SocketEndpointInfo *wsnet_endpoint_info(Socket *s, bool peer)
{
    return NULL;
}

static const struct SocketVtable wsnet_sockvt = {
    .plug = wsnet_plug,
    .close = wsnet_close,
    .write = wsnet_write,
    .write_oob = wsnet_write_oob,
    .write_eof = wsnet_write_eof,
    .set_frozen = wsnet_set_frozen,
    .socket_error = wsnet_socket_error,
    .endpoint_info = wsnet_endpoint_info,
};

Socket *ws_new_connection(const char *hostname, int port,
                          Plug *plug, Conf *conf)
{
    struct WSSocket *ws = snew(struct WSSocket);
    memset(ws, 0, sizeof(*ws));

    ws->vt = &wsnet_sockvt;
    ws->plug = plug;
    ws->s = INVALID_SOCKET;
    ws->target_host = dupstr(hostname);
    ws->target_port = port;

    ws->proxy_host = dupstr(conf_get_str(conf, CONF_ws_proxy_host));
    ws->proxy_port = conf_get_int(conf, CONF_ws_proxy_port);
    ws->proxy_path = dupstr(conf_get_str(conf, CONF_ws_proxy_path));
    ws->use_tls = conf_get_bool(conf, CONF_ws_proxy_tls);

    ws->recv_ic.fn = wsnet_recv_idempotent;
    ws->recv_ic.ctx = ws;
    ws->error_ic.fn = wsnet_error_idempotent;
    ws->error_ic.ctx = ws;
    ws->connect_ic.fn = wsnet_connect_idempotent;
    ws->connect_ic.ctx = ws;

    InitializeCriticalSection(&ws->lock);
    bufchain_init(&ws->send_queue);
    bufchain_init(&ws->recv_queue);

    DWORD tid;
    ws->thread = CreateThread(NULL, 0, wsnet_thread, ws, 0, &tid);
    if (!ws->thread) {
        sfree(ws->target_host);
        sfree(ws->proxy_host);
        sfree(ws->proxy_path);
        sfree(ws);
        return NULL;
    }

    return (Socket *)ws;
}
