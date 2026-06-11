# PuTTYPlus 测试与 Debug 报告

## 测试概要

| 测试项 | 结果 |
|--------|------|
| 编译构建 (cmake --build --clean-first) | ✅ 成功 (0 错误) |
| test_host_strfoo | ✅ 8/8 passed |
| test_decode_utf8 | ✅ 全部通过 |
| test_unicode_norm | ✅ 全部通过 |
| test_tree234 | ✅ 全部通过 |
| test_wildcard | ✅ 全部通过 |
| test_cert_expr | ✅ 全部通过 |
| test_conf | ✅ 通过 (含 wsnet.c 链接) |
| test_terminal | ✅ Test suite passed |
| test_lineedit | ✅ Test suite passed |
| testcrypt | ✅ 正常 |
| bidi_test / bidi_gettype | ✅ 正常 |
| test_split_into_argv | ✅ 正常 |
| test_screenshot | ✅ 正常 (需参数) |
| plink / pscp / psftp / puttygen / pageant | ✅ 构建成功 |
| puttyplus (GUI) / puttyplus-term (控制台) | ✅ 构建成功 |

## 严重问题 (Critical)

### 1. WSS/TLS 未实现 — `ws_proxy_tls` 配置无效

- **位置**: `windows/wsnet.c:531`
- **问题**: `ws->use_tls = conf_get_bool(conf, CONF_ws_proxy_tls)` 读取了配置但在 `wsnet_thread()` 中从未使用。无论 "Use TLS (WSS)" 是否勾选，始终使用明文 WS 连接。
- **影响**: 用户以为连接加密（WSS），实际是明文 HTTP WebSocket。中间人可截获 SSH 流量。
- **修复**: 要么实现 TLS（schannel/openssl），要么从 UI(`config.c:2503-2505`) 移除复选框。

### 2. `rand()` 用于 WebSocket Masking Key

- **位置**: `windows/wsnet.c:101-102, 131-133`
- **问题**: WS 掩码密钥和数据帧掩码使用 `rand()` 生成，违反 **RFC 6455 §10.3**（必须不可预测）。
- **修复**: 替换为 `CryptGenRandom()` 或 `BCryptGenRandom()`。

### 3. `wsnet_write_eof` 发送格式错误的 Close 帧

- **位置**: `windows/wsnet.c:488-491`
- **问题**: 设置 MASK=1 但未发送 4 字节 mask key。RFC 6455 要求 masked 帧必须跟 4 字节 masking key。
- **修复**: 补全 mask key 字节。

## 高优先级问题 (High)

### 4. 工作线程竞态条件

- **位置**: `windows/wsnet.c:281-394`
- **问题**: `ws->closing`、`ws->s` 在工作线程中访问未加锁，而主线程 `wsnet_close()` 可能同时 `closesocket(ws->s)`。
- **修复**: 用 `InterlockedExchange` 或统一临界区保护共享状态。

### 5. 线程终止超时导致 Use-After-Free

- **位置**: `windows/wsnet.c:452`
- **问题**: `WaitForSingleObject(ws->thread, 5000)` 超时后仍然 `sfree(ws)`，工作线程可能继续访问已释放内存。
- **修复**: 用 Event 对象通知线程退出，等待无限超时。

## 中优先级问题 (Medium)

### 6. `is_local_host()` 不完整

- **位置**: `ssh/ssh.c:20-35`
- **问题**: 不检查 IPv6 ULA (`fc00::/7`)、链路本地 (`169.254.x.x`)、带作用域 IPv6 (`::1%lo`)、IPv4-mapped IPv6。
- **修复**: 增加上述地址判断。

### 7. JSON 响应解析不安全

- **位置**: `windows/wsnet.c:382-392`
- **问题**: 用 `strstr()` 子串匹配而非 JSON 解析，缓冲区仅 4KB 截断风险。
- **修复**: 精确字符串匹配或轻量 JSON 解析器。

### 8. 缺少 `Sec-WebSocket-Accept` 校验

- **位置**: `windows/wsnet.c:256-263`
- **问题**: 仅检查 HTTP 101，不验证 Accept Key SHA-1 签名。
- **修复**: 实现 RFC 6455 §4 的 Accept Key 验证。

### 9. `conpty_size` 不验证 pseudoconsole 句柄

- **位置**: `windows/conpty.c:340-347`
- **问题**: `conpty_terminate()` 设为 `INVALID_HANDLE_VALUE` 后，`conpty_size` 仍调用 `p_ResizePseudoConsole`。
- **修复**: 添加句柄有效性检查。

### 10. `send()` 返回值未检查

- **位置**: `windows/wsnet.c:120, 228, 351`
- **问题**: 阻塞 socket 理论上也可能部分发送。
- **修复**: 循环检查返回值确保全部发送。

## 低优先级问题 (Low)

| # | 问题 | 位置 | 建议 |
|---|------|------|------|
| 11 | `wsnet_endpoint_info` 返回 NULL | `wsnet.c:500-503` | 实现端点信息返回 |
| 12 | 连接超时硬编码 30s | `wsnet.c:194` | 使用 `CONF_connect_timeout` |
| 13 | 每帧 malloc/free 掩码缓冲区 | `wsnet.c:122-126` | 栈分配或重用缓冲区 |
| 14 | 栈上 64KB 帧缓冲区 | `wsnet.c:275` | 考虑堆分配 |

## 编译警告

仅有 `windows/wsnet.c` 中 `container_of` 宏的类型检查警告 (`-Wcompare-distinct-pointer-types`)，来自上游 `defs.h:242` TYPECHECK 宏，属误报。在所有 6 个目标中重复出现。

## 修复优先级排序

1. **🔴 严重**: WSS/TLS 未实现 → `wsnet.c` + `config.c`
2. **🔴 严重**: `rand()` 掩码密钥 → `wsnet.c:101,133`
3. **🔴 严重**: Close 帧格式错误 → `wsnet.c:488-491`
4. **🟠 高**: 工作线程竞态条件 → `wsnet.c:281+`
5. **🟠 高**: 线程终止 UAF → `wsnet.c:452`
6. **🟡 中**: `is_local_host()` IPv6 支持 → `ssh/ssh.c:33`
7. **🟡 中**: `Sec-WebSocket-Accept` 校验 → `wsnet.c:256`
8. **🟡 中**: JSON 解析安全 → `wsnet.c:382`
9. **🟡 中**: `conpty_size` 句柄检查 → `conpty.c:340`
10. **🟡 中**: `send()` 返回值检查 → `wsnet.c`

## 项目健康度总评

- 构建系统: ✅ 稳定
- 上游测试: ✅ 全部通过
- 核心架构: ✅ 设计合理
- WebSocket 实现: ⚠️ 有多处安全问题需修复
- ConPTY 后端: ✅ 质量良好，轻微健壮性问题
- 配置系统: ✅ 兼容性好
- 文档/计划: ✅ PLAN.md 清晰完整
