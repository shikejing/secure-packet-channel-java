# secure-packet-channel-java

会话级报文加密与完整性通道，面向实时对战场景。收发两端只在本进程内通过
`Consumer<byte[]>` 回调（内存管道 / 本地回环）交互，不依赖任何外部服务。

## 功能总览

| 能力 | 实现 |
| --- | --- |
| 密钥协商 | X25519 ECDH + HKDF-SHA256，三次握手（HELLO / HELLO2 / FIN），双向密钥确认 |
| 报文保护 | AES-256-GCM，帧头作为 AAD；nonce 由 (epoch, seq) 确定性派生，绝不重复 |
| 重放保护 | 每会话滑动重放窗口（数据、控制两个独立序号空间） |
| 有序交付 | 接收侧重排缓冲，恰好一次、按序交付给上层 |
| 密钥轮换 | 链式密钥派生（chain key），ROTATE / ROTATE_ACK 协议，超时回退 |
| 断线重连 | 新会话全新会话 id 与密钥；旧会话报文一律拒绝 |
| 并发隔离 | 每会话一把监视器锁；出站帧在锁外经队列 FIFO 排空 |
| 可复现性 | 可注入 `SecureRandom` 与时钟；固定种子下逐字节复现 |

## 快速开始

```java
ChannelConfig config = ChannelConfig.defaults();
SecureChannelEndpoint a = new SecureChannelEndpoint(config, randomA, clock);
SecureChannelEndpoint b = new SecureChannelEndpoint(config, randomB, clock);
a.setSink(b::onBytes);   // 内存管道：a 的出站直接喂给 b
b.setSink(a::onBytes);

HandshakeHandle h = a.connect();        // 同步管道下握手内联完成
long sid = h.sessionId().orElseThrow();

a.send(sid, "hello".getBytes());
byte[] msg = b.poll(sid);               // 按序、恰好一次

a.rotate(sid);                          // 密钥轮换，同步管道下内联完成
a.close(sid);
```

超时与重试由 `tick()` 驱动：调用方按自己的节奏调用 `endpoint.tick()`，
端点用构造时注入的时钟判断超时并重传 HELLO / ROTATE，或宣布失败 / 回退。

## 通道语义

### 交付保证

- 上层通过 `poll(sessionId)` 读取消息：**按发送序、恰好一次**。
- 乱序到达的报文先进入重排缓冲；缺口（丢失或被篡改的序号）在重放窗口
  滑过之后被**确定性地跳过**——因为该序号此后永远不可能再被接受。
  已入缓冲的报文不会被跳过规则吞掉。
- 每条报文的处理都在会话监视器内完成：任何时刻上层要么看到完整处理
  后的状态，要么完全看不到，不存在"处理了一半"的中间态。

### 拒绝分类（`RejectReason`）

| 类别 | 含义 |
| --- | --- |
| `MALFORMED_PACKET` | 帧无法解析 |
| `UNKNOWN_SESSION` | 会话 id 从未存在 |
| `STALE_SESSION` | 会话 id 属于已关闭/被替换的旧会话（重连场景） |
| `SESSION_CLOSED` | 会话已关闭 |
| `INTEGRITY_FAILURE` | AEAD 校验失败：报文在链路上被改动 |
| `REPLAY_DUPLICATE` | 序号已被消费（原样重放） |
| `TOO_OLD` | 序号落在重放窗口之后 / 交付点之后，永不再接受 |
| `STALE_EPOCH` | 密钥世代过旧（只保留当前 + 上一世代） |
| `BUFFER_OVERFLOW` | 超出在途缓冲上界，未被标记，可稍后重试 |
| `UNEXPECTED_CONTROL` | 与当前协议状态不符的控制帧 |

### 协商失败分类（`HandshakeFailure`，与完整性失败严格区分）

`PEER_KEY_INVALID`（对端公钥非法/低阶点）、`VERSION_MISMATCH`、
`TRANSCRIPT_MISMATCH`（密钥确认 MAC 不符，握手被篡改）、
`TIMED_OUT`（服务端等待 FIN 超时）、`RETRIES_EXHAUSTED`（重传预算耗尽）、
`ILLEGAL_STATE`。

### 密钥材料安全

- 会话密钥、链密钥、ECDH 共享秘密只存在于包私有字段中；
  `toString()`、异常消息、统计输出均不含密钥材料。
- 会话关闭 / 轮换提交 / 轮换回退时，旧密钥与链密钥被尽力擦除
  （`SecretKey.destroy()` / 数组清零）。

## 重放窗口

- 数据与控制（ROTATE / ROTATE_ACK / CLOSE）使用**两个独立的序号空间**，
  各自维护一个滑动窗口；序号在会话内单调递增，**跨密钥世代不复位**，
  因此 (epoch, seq) 派生的 GCM nonce 对同一把钥匙永不重复。
- 判定完全确定：窗口内未见过 → 接受；已见过 → `REPLAY_DUPLICATE`；
  落后于窗口 → `TOO_OLD`（一旦落后，永不再被接受）。
- 轮换边界：接收方同时接受当前世代与上一世代的报文（在途报文不丢失、
  不错序）；落后两个世代及以上 → `STALE_EPOCH`。

## 密钥轮换

1. 发起方派生新链密钥与新一代会话密钥，发送 ROTATE（旧钥匙保护）。
2. 接收方验证后**立即提交**新世代，并用**新钥匙**回 ROTATE_ACK；
   ACK 与提交在同一临界区内入队，新世代数据报文不可能越过 ACK。
3. 发起方收到 ACK 后提交；旧世代钥匙保留一代用于在途报文。
4. ACK 超时未达：按 `maxRetries` 重传，最终**回退**到旧世代，
   会话继续可用（`rotationsRolledBack` 计数 +1）。
5. 双方同时发起轮换时，客户端发起的胜出，服务端回退自己的尝试——
   两端结论一致。

## 断线重连

- 重连 = 全新握手：新的会话 id、新的密钥、序号空间从零开始。
- 旧会话 id 被端点记住（有界集合），旧报文得到 `STALE_SESSION` 而非
  `UNKNOWN_SESSION`；同一报文不会被处理两次，也不会出现序号回退/跳变
  造成的错位（序号空间按会话隔离）。

## 可配置项（`ChannelConfig`）

| 配置 | 默认 | 含义 |
| --- | --- | --- |
| `replayWindowSize` | 1024 | 重放窗口大小（序号） |
| `maxInFlight` | 256 | 接收侧重排缓冲上界（未交付报文数） |
| `timeoutMillis` | 2000 | 握手 / 轮换的超时时间 |
| `maxRetries` | 3 | 握手 / 轮换的最大重传次数 |

- `endpoint.updateConfig(...)` 只影响**之后处理**的报文；在途操作
  （进行中的握手、轮换）沿用旧配置直至结束，不会停在中间态。
- 取消 / 超时路径（握手失败、轮换回退）都会把会话恢复到一个自洽状态。

## 可观测统计（`ChannelStats`）

`accepted()`、`rejectedSnapshot()`（按 `RejectReason` 分类）、
`handshakesCompleted()`、`handshakeFailureSnapshot()`（按
`HandshakeFailure` 分类）、`rotationsCommitted()`、`rotationsRolledBack()`。
统计只含计数，不含任何密钥材料或报文内容。

## 可复现性

- 构造端点时注入固定种子的 `SecureRandom`（测试用
  `DeterministicRandom`，SHA-256 计数器 DRBG）与可控时钟
  （测试用 `MutableClock`）。
- 在固定种子 + 相同输入序列下，线上字节流与交付给上层的消息序列
  **逐条一致**（见 `DeterminismTest`），可精确复现历史问题。

## 运行测试

```bash
mvn test
```

测试覆盖：协商失败（版本不符 / 篡改握手 / 重传耗尽）、报文篡改
（密文 / 帧头 AAD）、重放与乱序与迟到、密钥轮换（在途报文、回退、
重试后成功）、断线重连（旧会话拒绝、不重复处理）、并发隔离
（多会话并发、异常输入隔离、轮换与流量并发）、配置变更与统计、
固定种子逐字节复现。
