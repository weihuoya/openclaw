# VNC Client vs wayvnc/neatvnc 功能对比

## 已完整实现

| 功能 | 状态 | 说明 |
|------|------|------|
| RFB 3.8 协议 | ✅ | 版本握手、初始化、消息循环 |
| Raw 编码 | ✅ | 基础像素传输 |
| CopyRect 编码 | ✅ | 区域复制 |
| RRE 编码 | ✅ | 2D 运行长度编码 |
| Hextile 编码 | ✅ | 分块多种子编码 |
| Tight 编码 | ✅ | Fill + JPEG + Basic Copy/Palette/Gradient，Gradient 已实现 |
| TRLE 编码 | ✅ | 带 RLE 的 tile 编码 |
| ZRLE 编码 | ✅ | zlib 压缩 + RLE |
| OpenH264 编码 | ✅ | 硬件解码抽象层，支持 Android MediaCodec 和 GStreamer |
| DesktopSize | ✅ | 桌面尺寸变更 |
| ExtendedDesktopSize | ✅ | 扩展桌面尺寸 + 多屏布局解析 |
| Cursor 伪编码 | ✅ | 光标形状更新 |
| CursorPos 伪编码 | ✅ | 光标位置更新 (-240) |
| JpegQuality | ✅ | JPEG 质量等级设置 |
| ExtendedClipboard | ✅ | 扩展剪贴板收发 |
| Fence | ✅ | 同步围栏 |
| ContinuousUpdates | ✅ | 连续更新模式 |
| None 认证 | ✅ | 无认证 |
| VNC Auth (DES) | ✅ | 密码挑战-响应 |
| VeNCrypt 协商 | ✅ | 版本 + 子类型选择 |
| VeNCrypt TLS | ✅ | TLS 流升级 + webpki 验证 |
| VeNCrypt X509 | ✅ | TLS + 证书验证 |
| RSA-AES 认证 + 流加密 | ✅ | 认证 + AES-128-CTR 流加密 |
| RSA-AES-256 认证 + 流加密 | ✅ | 认证 + AES-128-CTR 流加密（key 截断） |
| Apple DH 认证 + 流加密 | ✅ | 认证 + AES-128-CTR 流加密（key 截断） |
| TLS 直接连接 | ✅ | `connect_tls()` 直接 TLS |
| WebSocket 传输 | ✅ | `connect_ws()` 支持 ws/wss |
| PointerEvent | ✅ | 鼠标/触摸输入，支持滚轮 |
| KeyEvent | ✅ | 按键输入 |
| ClientCutText | ✅ | 剪贴板发送（legacy + extended）|
| 键盘 LED 状态 | ✅ | QEMU 扩展 255/1 解析 |
| Android EGL/GLES3 | ✅ | Surface 渲染 |

---

## 部分实现 / 有缺陷

| 功能 | 状态 | 问题 |
|------|------|------|
| **VeNCrypt TLS** | ✅ | TLS 流升级完成，使用 rustls + webpki-roots 验证。 |
| **RSA-AES 流加密** | ✅ | 认证后流包装为 `AesCfbStream`（AES-128-CTR）。 |
| **Apple DH 流加密** | ✅ | 认证后密钥截断为 16 字节，包装为 `AesCfbStream`。 |
| **Tight Gradient** | ✅ | 实现 `decode_basic_gradient` 填充解码。 |
| **CursorPos** | ✅ | 编码 `-240` 触发 `VncEvent::CursorPos { x, y }`。 |
| **JpegQuality** | ✅ | 编码定义存在，可发送给服务器。 |
| **X509 证书认证** | ✅ | 使用 TLS + webpki roots 验证（暂无客户端证书）。 |
| **键盘 LED 状态同步** | ✅ | 解析 QEMU 扩展消息 255/1 触发 `VncEvent::LedState`。 |
| **WebSocket 传输** | ✅ | `connect_ws(url)` 支持 ws:// 和 wss://。 |
| **多显示器布局** | ✅ | `ExtendedDesktopSize` 解析并触发 `VncEvent::ScreenLayout`。 |

---

## 缺失功能（wayvnc/neatvnc 支持，排除 QEMU 特定）

| 功能 | 优先级 | 说明 |
|------|--------|------|
| **正常化指针输入** | 无需 | 标准 RFB PointerEvent 使用 u16 坐标（0-65535），本身就是归一化。neatvnc 服务端负责映射。 |
| **音频传输** | ✅ | QEMU 音频扩展：start/stop/data 操作。 |
| **SASL 认证** | ✅ | 支持 PLAIN、SCRAM-SHA-1、SCRAM-SHA-256。 |
| **DesktopName 事件** | 无需 | `DesktopName` 伪编码 (-307) 已实现，触发 `NameChanged`。 |
| **帧变换/旋转** | ✅ | Transform 枚举 + Framebuffer::read_pixel。 |
| **GBM/DMA-BUF** | 无需 | 仅适用于服务端零拷贝。 |
| **JPEG 质量自适应** | 低 | 客户端可发送 `JpegQuality` 编码，但自适应带宽估计算法未实现。 |

---

## 关键阻塞项

如果目标是连接 wayvnc，以下问题需要修复：

- 无。所有 wayvnc 核心功能（除音频、旋转、SASL 外）已实现。若 wayvnc 配置为 `enable_auth=false`，客户端可直接连接。

## 建议修复顺序（低优先级）

1. 低：正常化指针输入（`0.0-1.0` 坐标）
2. 低：JPEG 质量自适应
3. 低：音频传输
4. 低：帧变换/旋转处理

