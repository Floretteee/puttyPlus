#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif

#define SECURITY_WIN32

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bcrypt.h>
#include <security.h>
#include <schnlsp.h>

#include "putty.h"
#include "network.h"

#define WS_MAGIC_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

struct TLSState {
    CredHandle hCred;
    bool cred_init;
    CtxtHandle hCtx;
    bool ctx_init;
    SecPkgContext_StreamSizes sizes;
    bool active;
    unsigned char encbuf[65536];
    size_t enc_len;
    unsigned char plainbuf[65536];
    size_t plain_pos;
    size_t plain_len;
    SECURITY_STATUS last_error;
};

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
    HANDLE thread_exit;
    CRITICAL_SECTION lock;

    bufchain send_queue;
    volatile long closing;
    bool closed;

    bufchain recv_queue;
    struct IdempotentCallback recv_ic;
    bool recv_queued;

    char *pending_error;
    char pending_error_buf[128];
    struct IdempotentCallback error_ic;
    bool error_queued;

    bool connected;
    struct IdempotentCallback connect_ic;
    bool connect_queued;

    bool frozen;

    struct TLSState tls;

    char local_addr[64];
    int local_port;
    char remote_addr[64];
    int remote_port;
};

static void wsnet_recv_idempotent(void *ctx);
static void wsnet_error_idempotent(void *ctx);
static void wsnet_connect_idempotent(void *ctx);

static int send_all(SOCKET s, const void *data, size_t len)
{
    const char *p = (const char *)data;
    size_t remaining = len;
    while (remaining > 0) {
        int sent = send(s, p, (int)remaining, 0);
        if (sent == SOCKET_ERROR) return SOCKET_ERROR;
        p += sent;
        remaining -= sent;
    }
    return (int)len;
}

/* --- TLS (SChannel) --- */

static void tls_cleanup(struct TLSState *tls)
{
    tls->active = false;
    tls->enc_len = 0;
    tls->plain_pos = 0;
    tls->plain_len = 0;
    if (tls->ctx_init) {
        DeleteSecurityContext(&tls->hCtx);
        tls->ctx_init = false;
    }
    if (tls->cred_init) {
        FreeCredentialsHandle(&tls->hCred);
        tls->cred_init = false;
    }
}

static bool tls_handshake(struct WSSocket *ws)
{
    struct TLSState *tls = &ws->tls;
    SCHANNEL_CRED sc = {0};
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
    sc.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
    TimeStamp expiry;

    SECURITY_STATUS ret = AcquireCredentialsHandleA(
        NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND,
        NULL, &sc, NULL, NULL, &tls->hCred, &expiry);
    if (ret != SEC_E_OK) { tls->last_error = ret; return false; }
    tls->cred_init = true;

    bool first_pass = true;
    ULONG attr;
    unsigned char recv_buf[16384];
    int recv_len = 0;

    ret = SEC_I_CONTINUE_NEEDED;
    while (ret == SEC_I_CONTINUE_NEEDED || ret == SEC_E_INCOMPLETE_MESSAGE) {
        if (ret == SEC_E_INCOMPLETE_MESSAGE) {
            int n = recv(ws->s, (char *)recv_buf + recv_len,
                         (int)sizeof(recv_buf) - recv_len, 0);
            if (n <= 0) { tls->last_error = SEC_E_INTERNAL_ERROR; tls_cleanup(tls); return false; }
            recv_len += n;
        }

        SecBuffer outBufs[1];
        outBufs[0].BufferType = SECBUFFER_TOKEN;
        outBufs[0].cbBuffer = 0;
        outBufs[0].pvBuffer = NULL;
        SecBufferDesc outDesc;
        outDesc.ulVersion = SECBUFFER_VERSION;
        outDesc.cBuffers = 1;
        outDesc.pBuffers = outBufs;

        SecBuffer inBufs[2];
        inBufs[0].BufferType = SECBUFFER_TOKEN;
        inBufs[0].pvBuffer = recv_buf;
        inBufs[0].cbBuffer = recv_len;
        inBufs[1].BufferType = SECBUFFER_EMPTY;
        inBufs[1].pvBuffer = NULL;
        inBufs[1].cbBuffer = 0;
        SecBufferDesc inDesc;
        inDesc.ulVersion = SECBUFFER_VERSION;
        inDesc.cBuffers = 2;
        inDesc.pBuffers = inBufs;

        ret = InitializeSecurityContextA(
            &tls->hCred,
            first_pass ? NULL : &tls->hCtx,
            (SEC_CHAR *)ws->proxy_host,
            ISC_REQ_ALLOCATE_MEMORY |
            ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT |
            ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM
#ifdef ISC_REQ_MANUAL_CRED_VALIDATION
            | ISC_REQ_MANUAL_CRED_VALIDATION
#endif
            ,
            0, 0,
            first_pass ? NULL : &inDesc,
            0,
            &tls->hCtx,
            &outDesc, &attr, &expiry);
        first_pass = false;
        if (ret == SEC_E_OK || ret == SEC_I_CONTINUE_NEEDED ||
            ret == SEC_E_INCOMPLETE_MESSAGE)
            tls->ctx_init = true;

        if (ret == SEC_E_OK || ret == SEC_I_CONTINUE_NEEDED) {
            if (outBufs[0].cbBuffer > 0 && outBufs[0].pvBuffer) {
                if (send_all(ws->s, outBufs[0].pvBuffer,
                             outBufs[0].cbBuffer) == SOCKET_ERROR) {
                    FreeContextBuffer(outBufs[0].pvBuffer);
                    tls->last_error = SEC_E_INTERNAL_ERROR;
                    tls_cleanup(tls);
                    return false;
                }
                FreeContextBuffer(outBufs[0].pvBuffer);
            }

            if (inBufs[1].BufferType == SECBUFFER_EXTRA && inBufs[1].cbBuffer > 0) {
                size_t extra = inBufs[1].cbBuffer;
                if (extra > (size_t)recv_len) {
                    tls->last_error = SEC_E_INTERNAL_ERROR;
                    tls_cleanup(tls);
                    return false;
                }
                memmove(recv_buf, recv_buf + recv_len - extra, extra);
                recv_len = (int)extra;
            } else {
                recv_len = 0;
            }

            if (ret == SEC_I_CONTINUE_NEEDED && recv_len == 0) {
                int n = recv(ws->s, (char *)recv_buf, (int)sizeof(recv_buf), 0);
                if (n <= 0) { tls->last_error = SEC_E_INTERNAL_ERROR; tls_cleanup(tls); return false; }
                recv_len = n;
            }
        }
    }

    if (ret != SEC_E_OK) { tls->last_error = ret; tls_cleanup(tls); return false; }

    ret = QueryContextAttributes(
        &tls->hCtx, SECPKG_ATTR_STREAM_SIZES, &tls->sizes);
    if (ret != SEC_E_OK) { tls->last_error = ret; tls_cleanup(tls); return false; }

    if (recv_len > 0) {
        if ((size_t)recv_len > sizeof(tls->encbuf)) {
            tls_cleanup(tls);
            tls->last_error = SEC_E_INTERNAL_ERROR;
            return false;
        }
        memcpy(tls->encbuf, recv_buf, (size_t)recv_len);
        tls->enc_len = (size_t)recv_len;
    }

    tls->active = true;
    return true;
}

static int tls_encrypt_send(struct WSSocket *ws,
                            const unsigned char *data, size_t len)
{
    struct TLSState *tls = &ws->tls;
    if (!tls->active) return send_all(ws->s, data, len);

    size_t total_sent = 0;
    while (total_sent < len) {
        size_t chunk = len - total_sent;
        if (tls->sizes.cbMaximumMessage > 0 &&
            chunk > tls->sizes.cbMaximumMessage)
            chunk = tls->sizes.cbMaximumMessage;

        size_t msgSize = tls->sizes.cbHeader + chunk + tls->sizes.cbTrailer;
        unsigned char *msg = (unsigned char *)malloc(msgSize);
        if (!msg) return SOCKET_ERROR;

        SecBuffer bufs[4];
        bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
        bufs[0].cbBuffer = tls->sizes.cbHeader;
        bufs[0].pvBuffer = msg;
        bufs[1].BufferType = SECBUFFER_DATA;
        bufs[1].cbBuffer = (unsigned long)chunk;
        bufs[1].pvBuffer = msg + tls->sizes.cbHeader;
        memcpy(bufs[1].pvBuffer, data + total_sent, chunk);
        bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
        bufs[2].cbBuffer = tls->sizes.cbTrailer;
        bufs[2].pvBuffer = msg + tls->sizes.cbHeader + chunk;
        bufs[3].BufferType = SECBUFFER_EMPTY;

        SecBufferDesc desc;
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers = 4;
        desc.pBuffers = bufs;

        SECURITY_STATUS ret = EncryptMessage(&tls->hCtx, 0, &desc, 0);
        if (ret != SEC_E_OK) { free(msg); return SOCKET_ERROR; }

        size_t total = (size_t)bufs[0].cbBuffer +
                       (size_t)bufs[1].cbBuffer +
                       (size_t)bufs[2].cbBuffer;
        int result = send_all(ws->s, msg, total);
        free(msg);
        if (result == SOCKET_ERROR)
            return SOCKET_ERROR;
        total_sent += chunk;
    }

    return (int)len;
}

static int tls_decrypt_recv(struct WSSocket *ws,
                            unsigned char *buf, size_t bufSize)
{
    struct TLSState *tls = &ws->tls;
    if (!tls->active) {
        return recv(ws->s, (char *)buf, (int)bufSize, 0);
    }

    if (tls->plain_pos < tls->plain_len) {
        size_t avail = tls->plain_len - tls->plain_pos;
        if (avail > bufSize) avail = bufSize;
        memcpy(buf, tls->plainbuf + tls->plain_pos, avail);
        tls->plain_pos += avail;
        if (tls->plain_pos == tls->plain_len) {
            tls->plain_pos = 0;
            tls->plain_len = 0;
        }
        return (int)avail;
    }

    for (;;) {
        if (tls->enc_len == 0) {
            int n = recv(ws->s, (char *)tls->encbuf,
                         (int)sizeof(tls->encbuf), 0);
            if (n <= 0) return n;
            tls->enc_len = (size_t)n;
        }

        SecBuffer bufs[4];
        bufs[0].BufferType = SECBUFFER_DATA;
        bufs[0].cbBuffer = (unsigned long)tls->enc_len;
        bufs[0].pvBuffer = tls->encbuf;
        bufs[1].BufferType = SECBUFFER_EMPTY;
        bufs[2].BufferType = SECBUFFER_EMPTY;
        bufs[3].BufferType = SECBUFFER_EMPTY;

        SecBufferDesc desc;
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers = 4;
        desc.pBuffers = bufs;

        SECURITY_STATUS ret = DecryptMessage(&tls->hCtx, &desc, 0, NULL);
        if (ret == SEC_E_INCOMPLETE_MESSAGE) {
            if (tls->enc_len == sizeof(tls->encbuf))
                return -1;
            int n = recv(ws->s, (char *)tls->encbuf + tls->enc_len,
                         (int)(sizeof(tls->encbuf) - tls->enc_len), 0);
            if (n <= 0) return n;
            tls->enc_len += (size_t)n;
            continue;
        }
        if (ret != SEC_E_OK)
            return -1;

        unsigned char *plain = NULL;
        size_t plain_len = 0;
        unsigned char *extra = NULL;
        size_t extra_len = 0;

        for (int i = 0; i < 4; i++) {
            if (bufs[i].BufferType == SECBUFFER_DATA) {
                plain = (unsigned char *)bufs[i].pvBuffer;
                plain_len = (size_t)bufs[i].cbBuffer;
            } else if (bufs[i].BufferType == SECBUFFER_EXTRA) {
                extra = (unsigned char *)bufs[i].pvBuffer;
                extra_len = (size_t)bufs[i].cbBuffer;
            }
        }

        if (extra_len > 0) {
            memmove(tls->encbuf, extra, extra_len);
            tls->enc_len = extra_len;
        } else {
            tls->enc_len = 0;
        }

        if (plain_len == 0)
            continue;

        if (plain_len > sizeof(tls->plainbuf))
            return -1;
        memcpy(tls->plainbuf, plain, plain_len);

        tls->plain_pos = 0;
        tls->plain_len = plain_len;

        size_t out = plain_len;
        if (out > bufSize) out = bufSize;
        memcpy(buf, tls->plainbuf, out);
        tls->plain_pos = out;
        if (tls->plain_pos == tls->plain_len) {
            tls->plain_pos = 0;
            tls->plain_len = 0;
        }
        return (int)out;
    }
}

static bool tls_has_pending_data(struct WSSocket *ws)
{
    struct TLSState *tls = &ws->tls;
    return tls->active &&
        (tls->enc_len > 0 || tls->plain_pos < tls->plain_len);
}

/* --- WebSocket frame helpers --- */

static void wsnet_generate_random(void *buf, size_t len)
{
    BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

static int wsnet_send_frame(struct WSSocket *ws,
                            const unsigned char *data, size_t len, int opcode)
{
    unsigned char header[14];
    size_t hdr_len = 0;

    header[hdr_len++] = (unsigned char)(0x80 | opcode);

    unsigned char mask[4];
    wsnet_generate_random(mask, 4);

    if (len < 126) {
        header[hdr_len++] = (unsigned char)(0x80 | len);
    } else if (len < 65536) {
        header[hdr_len++] = (unsigned char)(0x80 | 126);
        header[hdr_len++] = (unsigned char)((len >> 8) & 0xFF);
        header[hdr_len++] = (unsigned char)(len & 0xFF);
    } else {
        header[hdr_len++] = (unsigned char)(0x80 | 127);
        uint64_t n = len;
        for (int i = 7; i >= 0; i--)
            header[hdr_len++] = (unsigned char)((n >> (i * 8)) & 0xFF);
    }

    for (int i = 0; i < 4; i++)
        header[hdr_len++] = mask[i];

    if (tls_encrypt_send(ws, header, hdr_len) == SOCKET_ERROR)
        return SOCKET_ERROR;

    if (len == 0)
        return 0;

    unsigned char *masked = (unsigned char *)malloc(len);
    if (!masked) return SOCKET_ERROR;
    for (size_t i = 0; i < len; i++)
        masked[i] = (unsigned char)(data[i] ^ mask[i & 3]);
    int ret = tls_encrypt_send(ws, masked, len);
    free(masked);
    return ret;
}

static void wsnet_generate_key(char *key_b64)
{
    unsigned char key_bytes[16];
    wsnet_generate_random(key_bytes, 16);

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

/* RFC 6455 Sec-WebSocket-Accept validation */
static bool validate_accept(const char *accept, const char *key)
{
    char concat[128];
    size_t klen = strlen(key);
    if (klen + sizeof(WS_MAGIC_GUID) > sizeof(concat)) return false;
    memcpy(concat, key, klen);
    memcpy(concat + klen, WS_MAGIC_GUID, sizeof(WS_MAGIC_GUID));

    unsigned char sha1[20];
    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM,
                                    NULL, 0) != 0)
        return false;
    BCRYPT_HASH_HANDLE hHash = NULL;
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    ULONG result = BCryptHashData(hHash, (PUCHAR)concat,
        (ULONG)(klen + sizeof(WS_MAGIC_GUID) - 1), 0);
    if (result != 0) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    BCryptFinishHash(hHash, sha1, 20, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    char expected_b64[32];
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int val = 0, bits = 0, out = 0;
    for (int i = 0; i < 20; i++) {
        val = (val << 8) | sha1[i];
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            expected_b64[out++] = b64[(val >> bits) & 0x3F];
        }
    }
    if (bits > 0)
        expected_b64[out++] = b64[(val << (6 - bits)) & 0x3F];
    while (out % 4)
        expected_b64[out++] = '=';
    expected_b64[out] = '\0';

    return strcmp(accept, expected_b64) == 0;
}

static const char *find_http_header(const char *headers, const char *name)
{
    size_t name_len = strlen(name);
    const char *line = headers;

    while (*line) {
        const char *next = strstr(line, "\r\n");
        size_t line_len = next ? (size_t)(next - line) : strlen(line);
        if (line_len > name_len && line[name_len] == ':' &&
            strnicmp(line, name, name_len) == 0) {
            const char *value = line + name_len + 1;
            while (*value == ' ' || *value == '\t')
                value++;
            return value;
        }
        if (!next)
            break;
        line = next + 2;
    }

    return NULL;
}

static int wsnet_json_escape(char *out, size_t outlen, const char *in)
{
    size_t pos = 0;

    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        if (*p == '"' || *p == '\\') {
            if (pos + 2 >= outlen) return -1;
            out[pos++] = '\\';
            out[pos++] = (char)*p;
        } else if (*p < 0x20) {
            if (pos + 7 >= outlen) return -1;
            sprintf(out + pos, "\\u%04x", *p);
            pos += 6;
        } else {
            if (pos + 1 >= outlen) return -1;
            out[pos++] = (char)*p;
        }
    }

    out[pos] = '\0';
    return (int)pos;
}

/* Structured JSON check for {"status":"ok"} */
static bool check_json_ok(const char *json)
{
    const char *p = json;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p++ != '{') return false;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (strncmp(p, "\"status\"", 8) != 0) return false;
    p += 8;
    while (*p == ' ' || *p == '\t') p++;
    if (*p++ != ':') return false;
    while (*p == ' ' || *p == '\t') p++;
    if (*p++ != '"') return false;
    if (strncmp(p, "ok", 2) != 0) return false;
    p += 2;
    if (*p++ != '"') return false;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p++ != '}') return false;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    return *p == '\0';
}

static void populate_endpoint_info(SOCKET s, struct WSSocket *ws)
{
    struct sockaddr_storage addr;
    int addrlen = sizeof(addr);

    if (getsockname(s, (struct sockaddr *)&addr, &addrlen) == 0) {
        if (addr.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
            ws->local_port = ntohs(sin->sin_port);
            getnameinfo((struct sockaddr *)sin, sizeof(*sin),
                        ws->local_addr, sizeof(ws->local_addr),
                        NULL, 0, NI_NUMERICHOST);
        } else if (addr.ss_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
            ws->local_port = ntohs(sin6->sin6_port);
            getnameinfo((struct sockaddr *)sin6, sizeof(*sin6),
                        ws->local_addr, sizeof(ws->local_addr),
                        NULL, 0, NI_NUMERICHOST);
        }
    }

    addrlen = sizeof(addr);
    if (getpeername(s, (struct sockaddr *)&addr, &addrlen) == 0) {
        if (addr.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
            ws->remote_port = ntohs(sin->sin_port);
            getnameinfo((struct sockaddr *)sin, sizeof(*sin),
                        ws->remote_addr, sizeof(ws->remote_addr),
                        NULL, 0, NI_NUMERICHOST);
        } else if (addr.ss_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
            ws->remote_port = ntohs(sin6->sin6_port);
            getnameinfo((struct sockaddr *)sin6, sizeof(*sin6),
                        ws->remote_addr, sizeof(ws->remote_addr),
                        NULL, 0, NI_NUMERICHOST);
        }
    }
}

/* --- Socket callbacks --- */

static const char *wsnet_socket_error(Socket *s)
{
    struct WSSocket *ws = container_of(s, struct WSSocket, vt);
    return ws->error;
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
#ifdef PUTTYPLUS_CLI_WS_WAKE
        if (winselcli_event != INVALID_HANDLE_VALUE)
            SetEvent(winselcli_event);
#endif
    }
}

static void wsnet_queue_error(struct WSSocket *ws)
{
    if (!ws->error_queued) {
        ws->error_queued = true;
        queue_idempotent_callback(&ws->error_ic);
#ifdef PUTTYPLUS_CLI_WS_WAKE
        if (winselcli_event != INVALID_HANDLE_VALUE)
            SetEvent(winselcli_event);
#endif
    }
}

static void wsnet_queue_connect(struct WSSocket *ws)
{
    if (!ws->connect_queued) {
        ws->connect_queued = true;
        queue_idempotent_callback(&ws->connect_ic);
#ifdef PUTTYPLUS_CLI_WS_WAKE
        if (winselcli_event != INVALID_HANDLE_VALUE)
            SetEvent(winselcli_event);
#endif
    }
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

    populate_endpoint_info(ws->s, ws);

    if (ws->use_tls) {
        if (!tls_handshake(ws)) {
            sprintf(ws->pending_error_buf,
                    "WebSocket: TLS handshake failed (0x%08lx)",
                    (unsigned long)ws->tls.last_error);
            ws->pending_error = ws->pending_error_buf;
            closesocket(ws->s);
            ws->s = INVALID_SOCKET;
            wsnet_queue_error(ws);
            return 1;
        }
    }

    char key_b64[64];
    wsnet_generate_key(key_b64);

    const char *path = ws->proxy_path && ws->proxy_path[0] ?
                       ws->proxy_path : "/p";

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

    if (tls_encrypt_send(ws, (const unsigned char *)handshake, hlen) != hlen) {
        ws->pending_error = "WebSocket: handshake send failed";
        tls_cleanup(&ws->tls);
        closesocket(ws->s);
        ws->s = INVALID_SOCKET;
        wsnet_queue_error(ws);
        return 1;
    }

    char resp[4096];
    unsigned char handshake_extra[4096];
    size_t handshake_extra_len = 0;
    int total = 0;
    bool got_headers = false;
    while (!got_headers) {
        int ret = tls_decrypt_recv(ws, (unsigned char *)resp + total,
                                   sizeof(resp) - 1 - total);
        if (ret <= 0) {
            ws->pending_error = "WebSocket: handshake failed";
            tls_cleanup(&ws->tls);
            closesocket(ws->s);
            ws->s = INVALID_SOCKET;
            wsnet_queue_error(ws);
            return 1;
        }
        total += ret;
        resp[total] = '\0';
        char *header_end = strstr(resp, "\r\n\r\n");
        if (header_end) {
            got_headers = true;
            size_t body_offset = (size_t)(header_end + 4 - resp);
            if ((size_t)total > body_offset) {
                handshake_extra_len = (size_t)total - body_offset;
                if (handshake_extra_len > sizeof(handshake_extra))
                    handshake_extra_len = sizeof(handshake_extra);
                memcpy(handshake_extra, resp + body_offset, handshake_extra_len);
                resp[body_offset] = '\0';
            }
        }
    }

    int status;
    char accept_hdr[128] = "";
    const char *accept_ptr = find_http_header(resp, "Sec-WebSocket-Accept");
    if (accept_ptr) {
        int alen = 0;
        while (accept_ptr[alen] && accept_ptr[alen] != '\r' && alen < 120)
            alen++;
        memcpy(accept_hdr, accept_ptr, alen);
        accept_hdr[alen] = '\0';
    }

    if (sscanf(resp, "HTTP/%*d.%*d %d", &status) != 1 || status != 101) {
        ws->pending_error = "WebSocket: server rejected upgrade";
        tls_cleanup(&ws->tls);
        closesocket(ws->s);
        ws->s = INVALID_SOCKET;
        wsnet_queue_error(ws);
        return 1;
    }

    if (!accept_hdr[0] || !validate_accept(accept_hdr, key_b64)) {
        ws->pending_error = "WebSocket: invalid Sec-WebSocket-Accept";
        tls_cleanup(&ws->tls);
        closesocket(ws->s);
        ws->s = INVALID_SOCKET;
        wsnet_queue_error(ws);
        return 1;
    }

    ws->connected = true;
    wsnet_queue_connect(ws);

    char escaped_host[256];
    if (wsnet_json_escape(escaped_host, sizeof(escaped_host),
                          ws->target_host) < 0) {
        ws->pending_error = "WebSocket: target host is too long";
        tls_cleanup(&ws->tls);
        closesocket(ws->s);
        ws->s = INVALID_SOCKET;
        wsnet_queue_error(ws);
        return 1;
    }

    char init_msg[512];
    int init_len = sprintf(init_msg,
        "{\"Host\":\"%s\",\"Port\":%d}\n",
        escaped_host, ws->target_port);
    wsnet_send_frame(ws, (const unsigned char *)init_msg, init_len, 0x2);

    unsigned char *frame_buf = (unsigned char *)malloc(65536);
    if (!frame_buf) {
        ws->pending_error = "WebSocket: out of memory";
        tls_cleanup(&ws->tls);
        closesocket(ws->s);
        ws->s = INVALID_SOCKET;
        wsnet_queue_error(ws);
        return 1;
    }
    size_t frame_pos = 0;
    if (handshake_extra_len > 0) {
        memcpy(frame_buf, handshake_extra, handshake_extra_len);
        frame_pos = handshake_extra_len;
    }

    bool expecting_json = true;
    int json_len = 0;
    char json_buf[4096];

    while (!InterlockedExchangeAdd(&ws->closing, 0)) {
        EnterCriticalSection(&ws->lock);
        size_t send_len = bufchain_size(&ws->send_queue);
        if (send_len > 0) {
            ptrlen data = bufchain_prefix(&ws->send_queue);
            wsnet_send_frame(ws,
                (const unsigned char *)data.ptr, data.len, 0x2);
            bufchain_consume(&ws->send_queue, data.len);
        }
        LeaveCriticalSection(&ws->lock);

        bool readable = tls_has_pending_data(ws);
        int sel = 0;
        if (!readable) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(ws->s, &rfds);
            tv.tv_sec = 0;
            tv.tv_usec = 100000;
            sel = select(0, &rfds, NULL, NULL, &tv);
            readable = sel > 0 && FD_ISSET(ws->s, &rfds);
        }

        if (readable) {
            int ret;
            if (ws->use_tls) {
                unsigned char tls_buf[65536];
                ret = tls_decrypt_recv(ws, tls_buf, sizeof(tls_buf));
                if (ret > 0) {
                    if ((size_t)ret > 65536 - frame_pos)
                        ret = (int)(65536 - frame_pos);
                    memcpy(frame_buf + frame_pos, tls_buf, (size_t)ret);
                    frame_pos += (size_t)ret;
                }
            } else {
                ret = recv(ws->s, (char *)frame_buf + frame_pos,
                           (int)(65536 - frame_pos), 0);
                if (ret > 0) frame_pos += (size_t)ret;
            }
            if (ret <= 0) {
                ws->pending_error = "WebSocket: connection lost";
                wsnet_queue_error(ws);
                break;
            }
        } else if (sel == SOCKET_ERROR) {
            ws->pending_error = "WebSocket: select failed";
            wsnet_queue_error(ws);
            break;
        }

        if (frame_pos > 0) {
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
                    payload_len = ((size_t)f[2] << 8) | f[3];
                    hdr = 4;
                } else if (payload_len == 127) {
                    if (frame_pos - consumed < 10) break;
                    payload_len = 0;
                    for (int i = 0; i < 8; i++)
                        payload_len = (payload_len << 8) | f[2 + i];
                    hdr = 10;
                }

                int mask_len = masked ? 4 : 0;
                if (frame_pos - consumed < hdr + (size_t)mask_len + payload_len)
                    break;

                unsigned char *payload = f + hdr;
                if (masked) {
                    unsigned char *mask = f + hdr;
                    payload = f + hdr + 4;
                    for (size_t i = 0; i < payload_len; i++)
                        payload[i] ^= mask[i & 3];
                    hdr += 4;
                }

                if (opcode == 0x8) {
                    InterlockedExchange(&ws->closing, 1);
                    break;
                }

                if (opcode == 0x9) {
                    wsnet_send_frame(ws, payload, payload_len, 0xA);
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
                json_buf[json_len] = '\0';
                if (!check_json_ok(json_buf)) {
                    ws->pending_error = "WebSocket: proxy rejected connection";
                    wsnet_queue_error(ws);
                    break;
                }
                json_len = 0;
                expecting_json = false;
            }
        }
    }

    if (InterlockedExchangeAdd(&ws->closing, 0) && ws->connected) {
        unsigned char close_frame[6] = {0x88, 0x80, 0, 0, 0, 0};
        unsigned char mask[4];
        wsnet_generate_random(mask, 4);
        memcpy(close_frame + 2, mask, 4);
        tls_encrypt_send(ws, close_frame, 6);
    }

    free(frame_buf);
    tls_cleanup(&ws->tls);

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

    EnterCriticalSection(&ws->lock);
    ws->recv_queued = false;
    while (!ws->frozen && bufchain_size(&ws->recv_queue) > 0) {
        ptrlen data = bufchain_prefix(&ws->recv_queue);
        LeaveCriticalSection(&ws->lock);
        plug_receive(ws->plug, 0, data.ptr, data.len);
        EnterCriticalSection(&ws->lock);
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
    InterlockedExchange(&ws->closing, 1);

    if (ws->thread_exit) SetEvent(ws->thread_exit);

    if (ws->s != INVALID_SOCKET) {
        closesocket(ws->s);
        ws->s = INVALID_SOCKET;
    }

    if (ws->thread) {
        WaitForSingleObject(ws->thread, INFINITE);
        CloseHandle(ws->thread);
    }

    if (ws->thread_exit) CloseHandle(ws->thread_exit);

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
    InterlockedExchange(&ws->closing, 1);
    if (ws->thread_exit) SetEvent(ws->thread_exit);
}

static void wsnet_set_frozen(Socket *s, bool is_frozen)
{
    struct WSSocket *ws = container_of(s, struct WSSocket, vt);
    bool queue_recv;

    EnterCriticalSection(&ws->lock);
    ws->frozen = is_frozen;
    queue_recv = !is_frozen && bufchain_size(&ws->recv_queue) > 0;
    LeaveCriticalSection(&ws->lock);

    if (queue_recv)
        wsnet_queue_recv(ws);
}

static SocketEndpointInfo *wsnet_endpoint_info(Socket *s, bool peer)
{
    struct WSSocket *ws = container_of(s, struct WSSocket, vt);
    SocketEndpointInfo *ei = snew(SocketEndpointInfo);
    memset(ei, 0, sizeof(*ei));

    const char *addr = peer ? ws->remote_addr : ws->local_addr;
    int port = peer ? ws->remote_port : ws->local_port;

    if (addr[0]) {
        ei->addr_text = dupstr(addr);
        ei->port = port;
        ei->log_text = dupprintf("%s:%d", addr, port);
    } else {
        ei->addr_text = NULL;
        ei->port = -1;
        ei->log_text = dupstr("WebSocket proxy");
    }

    return ei;
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

#ifdef PUTTYPLUS_CLI_WS_WAKE
    winselcli_setup();
#endif

    ws->recv_ic.fn = wsnet_recv_idempotent;
    ws->recv_ic.ctx = ws;
    ws->error_ic.fn = wsnet_error_idempotent;
    ws->error_ic.ctx = ws;
    ws->connect_ic.fn = wsnet_connect_idempotent;
    ws->connect_ic.ctx = ws;

    ws->thread_exit = CreateEvent(NULL, TRUE, FALSE, NULL);

    InitializeCriticalSection(&ws->lock);
    bufchain_init(&ws->send_queue);
    bufchain_init(&ws->recv_queue);

    DWORD tid;
    ws->thread = CreateThread(NULL, 0, wsnet_thread, ws, 0, &tid);
    if (!ws->thread) {
        if (ws->thread_exit) CloseHandle(ws->thread_exit);
        sfree(ws->target_host);
        sfree(ws->proxy_host);
        sfree(ws->proxy_path);
        sfree(ws);
        return NULL;
    }

    return (Socket *)ws;
}
