# secure-packet-channel-java

会话级报文加密与完整性通道。收发两端只在本进程内通过本地回环 / 内存管道
（`LoopbackTransport`）交互，不依赖任何外部服务，全部结论可在本地复现与验证。

## 快速开始

```java
LoopbackTransport[] link = LoopbackTransport.pair();
SecureSession client = SecureSession.client(1L, link[0], ChannelConfig.defaults(), rng1);
SecureSession server = SecureSession.server(1L, link[1], ChannelConfig.defaults(), rng2);

client.startHandshake();
server.accept();              // 处理 HELLO 并回复 HELLO_ACK
client.completeHandshake();   // 派生会话密钥，进入 ESTABLISHED

client.send("hello".getBytes(StandardCharsets.UTF_8));
Optional<Message> msg = server.pollMessage();
```

测试辅助 `SessionManager.establishedPair(...)` 可一步建好一对已握手会话。

## 通道语义

### 密钥协商与派生

- 握手使用 X25519 临时密钥对，主密钥经 HKDF-SHA256 派生，
  盐绑定 `sessionId | generation | 双方临时公钥`，任何第三方无法重放协商记录。
- 每个会话、每个会话代（每次重连）都重新协商，密钥互相独立。
- 每条报文使用 AES-CTR 加密 + HMAC-SHA256 标签（Encrypt-then-MAC），
  密钥代与序号作为关联数据参与认证。
- 密钥材料不会出现在日志、异常信息或任何对外输出中
  （`KeyMaterial.toString()` 恒为 `KeyMaterial[redacted]`）。
- 协商失败抛出 `HandshakeException`，携带 `HandshakeFailure`
  （`MALFORMED_HELLO` / `UNSUPPORTED_VERSION` / `SESSION_MISMATCH` /
  `INVALID_RESUME_STATE` / `TIMEOUT`），与报文完整性失败
  （接收路径统计中的 `RejectReason.INTEGRITY_FAILURE`）完全区分。

### 完整性与篡改

- 任何被改动的报文（密文、标签、序号、密钥代）都在校验阶段被拒绝，
  明文不会交给上层；校验失败不计入重放窗口，不会毒化会话状态。
- 无法解析的报文计为 `MALFORMED` 拒绝。

### 序号与重放窗口

接收端维护滑动重放窗口（默认 64），语义确定：

| 情况 | 处理 | 拒绝类别 |
| --- | --- | --- |
| seq > highest 且超前不超过窗口 | 接受，窗口前移 | — |
| seq 超出 highest + 窗口 | 拒绝 | `SEQUENCE_AHEAD_OF_WINDOW` |
| highest - 窗口 < seq ≤ highest 且未见过 | 接受（乱序容忍） | — |
| 窗口内已见过 | 拒绝 | `DUPLICATE` |
| seq ≤ highest - 窗口 | 拒绝，且不会复活 | `SEQUENCE_TOO_OLD` |

窗口内乱序报文按到达顺序交付；同一报文永远不会被交付两次。

### 密钥轮换

- `initiateRotation()` 发起轮换（ROTATE / ROTATE_COMMIT / ROTATE_ABORT 三次控制交互）。
- 切换期间接收端同时保留新旧两代密钥（最近 2 代），在途报文不丢失、不错序；
  切换边界由报文头部的密钥代字段明确标识。
- 轮换失败或被中止（`abortRotation()` / 对端 ABORT）时回退到上一代密钥，
  会话继续使用旧密钥收发，回退计入 `rotationRollbacks` 统计。

### 断线重连与状态恢复

- 客户端 `startReconnect(newTransport)` + `completeHandshake()`，
  服务端 `attachTransport(newTransport)` 后在正常接收路径处理 RESUME。
- 每次重连 `generation` 单调递增并重新协商密钥；旧会话代的报文
  （数据或 RESUME）一律被拒绝（完整性失败或 `STALE_GENERATION`）。
- 恢复时双方交换序号状态并校验：序号只前进不回退；
  序号回退或声称收到未发送序号的恢复请求以 `INVALID_RESUME_STATE` 拒绝，
  且不影响原会话继续使用。

### 并发与隔离

- `SecureSession` 内部全部状态变更在会话锁内完成，上层不会读到半处理状态。
- 会话之间不共享可变状态；`SessionManager` 只是注册表。
  单个会话的异常输入或掉线不影响其他会话（见 `ConcurrencyTest`）。

### 可复现性

`CryptoUtil.deterministicRandom(seed)` 提供确定性随机源：固定随机种子与
相同输入序列下，线上字节与交付结果逐条一致（见 `DeterminismTest`），
可用于复现历史问题。

## 可配置项（`ChannelConfig`）

| 配置 | 默认 | 含义 |
| --- | --- | --- |
| `replayWindowSize` | 64 | 重放窗口大小（1..1024） |
| `maxInFlight` | 256 | 已解密未交付报文的缓冲上界，超限以 `BUFFER_FULL` 拒绝 |
| `handshakeTimeoutMillis` | 5000 | 握手 / 恢复单次等待超时 |
| `maxHandshakeRetries` | 3 | 握手 / 恢复超时后的重发次数 |
| `rotationIntervalMillis` | 60000 | 建议的轮换间隔（由上层调度参考） |

- 配置为不可变对象，`updateConfig` 原子替换，只影响后续报文；
  进行中的处理不会读到半更新状态，取消 / 超时不会让会话停在中间态。
- 每个会话的接受 / 拒绝统计通过 `stats()` 观测（`ChannelStats.Snapshot`
  为不可变副本），拒绝按 `RejectReason` 分类计数。

## 拒绝类别一览（`RejectReason`）

`SESSION_NOT_ESTABLISHED`、`SESSION_CLOSED`、`STALE_GENERATION`、`STALE_EPOCH`、
`INTEGRITY_FAILURE`、`SEQUENCE_AHEAD_OF_WINDOW`、`SEQUENCE_TOO_OLD`、
`DUPLICATE`、`MALFORMED`、`BUFFER_FULL`。

## 线上格式

```
magic(2) | version(1) | type(1) | keyEpoch(4) | sequence(8)
| nonceLen(2) nonce | ctLen(4) ciphertext | tagLen(2) tag
```

控制报文（HELLO / HELLO_ACK / RESUME / RESUME_ACK / RESUME_REJECT /
ROTATE / ROTATE_COMMIT / ROTATE_ABORT）复用同一帧格式，负载为控制编码，
只携带临时公钥与序号状态，不含任何密钥材料。

## 测试

```bash
mvn test
```

覆盖：协商失败（`HandshakeTest`）、报文篡改（`IntegrityTest`）、
重放与乱序（`ReplayWindowTest`）、密钥轮换（`KeyRotationTest`）、
断线重连（`ReconnectTest`）、并发隔离（`ConcurrencyTest`）、
配置与统计（`ConfigTest`）、可复现性（`DeterminismTest`）。
