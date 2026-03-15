# 咕咕嘎嘎 无头客户端

一个用于研究某神人游戏登录链路的 Python 无头客户端，当前已打通以下流程：

- 拉取 launcher / resource / remote config
- **通行证扫码登录
- U8 鉴权与选服
- 调用 `GameAssembly.dll` 中的 SRSA 逻辑加密 `CsLogin`
- 与游戏 TCP 服务器建立连接并完成登录

当前实现以 Windows 环境为前提，因为登录加密依赖本地 `GameAssembly.dll`。

## 环境要求

- Python 3.12 或相近版本
- Windows
- 可用的 `GameAssembly.dll`

安装依赖：

```bash
pip install -r requirements.txt
```

如果要使用实验性 WebUI，还需要安装新增的 Web 依赖（已写入 `requirements.txt`）：

```bash
pip install -r requirements.txt
```

## 运行方式

最常用命令：

```bash
python main.py --dll-dir "C:\path\to\Data"
```

其中 `--dll-dir` 需要指向包含 `GameAssembly.dll` 的目录，例如：

```bash
python main.py --dll-dir "C:\Users\hyh28\Documents\Hg\Data"
```

默认行为：

- 登录成功后进入全屏交互式 TUI
- 长连接和心跳会继续保持
- 状态、结果、日志、命令输入会分区显示
- 默认会过滤掉高频心跳日志，避免刷屏影响操作

如果你想沿用旧的纯日志模式，不进入交互界面：

```bash
python main.py --dll-dir "C:\Users\hyh28\Documents\Hg\Data" --no-cli
```

可选参数：

- `--config-dir`：配置缓存目录，默认 `./Data/tmp`
- `--skip-config`：跳过配置拉取，直接使用已有流程
- `--oversea`：使用海外环境
- `--server-id`：指定服务器 ID
- `--qrcode-dir`：二维码输出目录，默认 `./qrcode`

## 实验性 CLI Plugin

`main.py` 现在默认会进入一个全屏交互式 TUI，启动后可直接输入命令执行 plugin。

当前已接入的命令行 plugin：

- `blueprint-query`

交互模式下可用命令：

- `help`
- `status`
- `plugins`
- `blueprint-query <share_code> [--timeout 秒] [--output summary|json|both]`
- `clear`
- `clear-logs`
- `toggle-ping-log`
- `exit` / `quit`

启动后直接查蓝图的典型流程：

```text
cmd> blueprint-query ABCD-1234
```

TUI 布局大致分成四块：

- 左侧：当前登录/会话状态
- 右上：命令执行结果
- 右下：日志窗口（默认过滤心跳）
- 底部：命令输入框

另外补了两个便于长期挂着用的命令：

- `clear-logs`：清空右下日志面板
- `toggle-ping-log`：切换是否过滤高频心跳日志

蓝图查询示例：

```bash
python main.py --dll-dir "C:\Users\hyh28\Documents\Hg\Data" --plugin blueprint-query --share-code "你的分享码"
```

如果希望查询完成后仍然继续保活长连接：

```bash
python main.py --dll-dir "C:\Users\hyh28\Documents\Hg\Data" --plugin blueprint-query --share-code "你的分享码" --wait-after-plugin
```

和 plugin 相关的参数：

- `--plugin blueprint-query`：指定执行蓝图查询 plugin
- `--share-code`：蓝图分享码
- `--plugin-timeout`：plugin 请求超时，默认 `10`
- `--plugin-output`：输出格式，可选 `summary` / `json` / `both`
- `--wait-after-plugin`：plugin 完成后继续保持 TCP 长连接
- `--no-cli`：不进入交互式 TUI，回退到旧的纯日志模式

## 实验性 WebUI

新增了一个实验性插件系统，并先接入了第一个 plugin：蓝图查询。

当前蓝图查询对齐自 `Il2CppInspector/types.cs` 中的这些协议定义：

- `CsFactoryQuerySharedBluePrint = 262`
- `ScFactoryQuerySharedBluePrint = 249`
- `CS_FACTORY_QUERY_SHARED_BLUE_PRINT`
- `SC_FACTORY_QUERY_SHARED_BLUE_PRINT`
- `CSD_FACTORY_BLUE_PRINT_DATA`

启动方式：

```bash
python web_app.py --dll-dir "C:\Users\hyh28\Documents\Hg\Data"
```

默认页面地址：

```text
http://127.0.0.1:18080
```

WebUI 当前提供：

- 会话登录与长连接保活
- 二维码图片展示
- 通过 share code 发送蓝图查询请求
- 展示蓝图基础信息、节点数、组件数和完整解析结果 JSON

## 目录结构

- [main.py](main.py)：命令行入口，串起整条登录流程
- [config/get_config.py](config/get_config.py)：launcher / resource / remote config 拉取与解密
- [login/passport_login.py](login/passport_login.py)：**通行证扫码登录
- [login/u8_login.py](login/u8_login.py)：U8 鉴权、取授权码、拉取服务器列表
- [tcp/tcp.py](tcp/tcp.py)：集中实现 `CsLogin` 构包、TCP 登录、响应解析
- [tcp/srsa_bridge.py](tcp/srsa_bridge.py)：调用 `GameAssembly.dll` 导出的 SRSA 桥接

运行时生成：

- `Data/tmp/*.json`：拉取到的配置缓存
- `qrcode/*.png`：扫码登录二维码

## 登录流程

1. 调用 launcher 接口获取客户端版本与资源信息
2. 下载并解密 `u8ExtraConfig.bin`
3. 获取 `network_config` / `game_config`
4. 通过**通行证扫码拿到 `channel_token`
5. 通过 U8 接口获取 `uid`、`grant_code` 和服务器列表
6. 生成客户端 RSA 密钥对
7. 构造 `CsLogin`，并通过 `GameAssembly.dll` 的 SRSA 逻辑加密
8. 发送 TCP 登录包，解析 `ScLogin`

## 当前 `CsLogin` 实现

`CsLogin` 已按 Il2CppInspector 导出的 `MSG_A1` 结构编码，主要字段如下：

- `a14`：branch tag，默认 `prod-obt-official`
- `a7`：资源版本，来自 `res_version.json` 中的 `res_version`
- `a6`：客户端版本，来自 `launcher_version.version`
- `a1`：uid
- `a2`：grant code
- `a8`：客户端 RSA 公钥，发送 PEM 原始字节
- `a9`：平台
- `a10`：区域
- `a12`：pay platform
- `a11`：环境
- `a21`：channel id
- `a22`：sub channel
- `client_language`
- `a23`：`DEVICE_INFO`

登录头部 checksum 取值为：

```python
zlib.crc32(cs_body_plain) & 0xFFFFFFFF
```

## 调试建议

登录失败时优先看 [tcp/tcp.py](tcp/tcp.py) 输出的这些日志：

- `CsLogin 字段详情`
- `build_cs_login_body 输出长度`
- `CsLogin 明文前 32 字节`
- `使用 checksum`
- `登录失败：...`

常见错误码：

- `33`：`ErrCommonClientVersionNotEqual`
- `34`：`ErrCommonClientResVersionNotEqual`
- `40`：`ErrLoginTokenInvalid`
- `41`：`ErrLoginMsgFormatInvalid`
- `44`：`ErrCommonPlatformInvalid`
- `77`：`ErrBranchVersionCheckFailed`
- `78`：`ErrChannelIdCheckFailed`

## 逆向定位

如果你本地有 Il2CppInspector 导出结果，可用它来交叉确认 protobuf 定义与方法地址。

与 `CsLogin` 直接相关的导出位置：

- `MSG_A1`：`Il2CppInspector/types.cs`
- `MSG_A1.InternalWriteTo`
- `MSG_A1.CalculateSize`
- `DEVICE_INFO.InternalWriteTo`
- `DEVICE_INFO.CalculateSize`

如果需要继续追登录明文来源，最直接的方法是在 IDA 中跟：

- `mono_method_h_get_code`
- `mono_method_h_set_code`

这样可以直接观察 SRSA 加密前后的内存内容。

## 说明

这个仓库面向协议研究与客户端实现验证，代码里保留了较多调试日志，默认不是面向生产环境的最小实现。

咕咕嘎嘎