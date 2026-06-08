# Modbus 串行链路安全扩展 6.3 参考实现

本项目实现《Modbus串行链路通信协议安全扩展技术要求》6.3 节描述的“基于口令或预共享密钥”的主从站参考端点，并提供命令行端点和浏览器界面。

RTU 帧本身包含从站地址、功能码和 CRC16。内容加密使用文档列出的 AES-GCM 模式，依赖 `cryptography`。

If a real UART interface is used in modbus_security_psk.by, the socket initialized here is only formal and not actually used. Every frame read and sent is completed on UART.

## 实现内容

- `ss_sk_open_req` / `ss_sk_open_cnf`
- `ss_sk_data_req` / `ss_sk_data_cnf`
- RTU 功能码 `0x00` 承载安全 APDU
- 预共享口令派生 SM2 曲线临时私钥和 ECC 随机点
- `S_M` / `S_H` 双向认证码验证
- `r_B` 广播密钥参数交换
- AES-GCM 内容加密后的 `ss_data_send`
- 示例 Modbus `0x03` 保持寄存器读取
- Web 页面输入主从站参数并显示主站读取到的从站寄存器

## 项目结构

```text
.
├── master_server.py              # 主站命令行端点
├── slave_server.py               # 从站命令行端点
├── modbus_security_psk.py        # 协议编解码、握手、加解密和 Modbus PDU 处理
├── web_frontend.py               # Web 服务和 JSON API
├── web/
│   ├── index.html                # 前端页面
│   ├── styles.css                # 页面样式
│   └── app.js                    # 前端交互逻辑
├── tests/
│   └── test_modbus_security_psk.py
├── requirements.txt
└── Modbus串行链路通信协议安全扩展技术要求.docx
```

## 环境要求

- Python 3.10 或更新版本
- 可创建本地 TCP/socket 连接
- Python 依赖：`cryptography>=42`

建议使用虚拟环境：

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

如果不使用虚拟环境，也可以直接在当前 Python 环境安装依赖：

```bash
python3 -m pip install -r requirements.txt
```

## 命令行启动

先启动从站：

```bash
python3 slave_server.py --host 127.0.0.1 --port 15020 --password modbus-psk-demo
```

另开一个终端启动主站并读取保持寄存器：

```bash
python3 master_server.py --host 127.0.0.1 --port 15020 --password modbus-psk-demo --start 0 --quantity 4
```

一次性从站示例：

```bash
python3 slave_server.py --host 127.0.0.1 --port 15020 --password modbus-psk-demo --once
```

主站成功读取后会输出类似内容：

```text
handshake ok server_id=0x1001000100000001 mode=aes_gcm ck=... civ=...
read holding registers start=0 quantity=4: [10, 20, 30, 40]
```

## Web 界面启动

启动浏览器界面：

```bash
python3 web_frontend.py --host 127.0.0.1 --port 8080
```

打开：

```text
http://127.0.0.1:8080
```

页面提交参数后，后端会临时启动一次模拟从站，由主站完成安全握手并读取保持寄存器，再把读取结果、会话模式、客户端 ID、服务器 ID、CK 和 CIV 显示在页面中。

## 参数说明

### 通用参数

`master_server.py` 和 `slave_server.py` 都支持以下参数：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--host` | `127.0.0.1` | TCP 监听或连接地址。 |
| `--port` | `15020` | TCP 监听或连接端口。 |
| `--slave-id` | `1` | Modbus 从站地址，范围 `1..247`，支持十进制或 `0x` 十六进制。 |
| `--password` | `modbus-psk-demo` | 主从站共享口令。两端必须一致，否则认证失败。 |

### 主站参数

`master_server.py` 额外支持：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--client-id` | `0x2001000100000001` | 主站客户端 ID，支持十进制或 `0x` 十六进制。 |
| `--start` | `0` | 保持寄存器起始地址。 |
| `--quantity` | `4` | 读取寄存器数量，范围 `1..125`。 |

### 从站参数

`slave_server.py` 额外支持：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--server-id` | `0x1001000100000001` | 从站服务器 ID，支持十进制或 `0x` 十六进制。 |
| `--registers` | `64` | 示例保持寄存器数量。寄存器值按 `(索引 + 1) * 10` 自动生成。 |
| `--once` | 关闭 | 处理一个主站连接后退出。 |

### Web 服务参数

`web_frontend.py` 支持：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--host` | `127.0.0.1` | Web 服务监听地址。 |
| `--port` | `8080` | Web 服务监听端口。 |

### Web 页面表单参数

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| 监听地址 | `127.0.0.1` | 临时模拟从站绑定地址。 |
| 监听端口 | `0` | 临时模拟从站端口。`0` 表示由系统自动分配空闲端口。 |
| 从站地址 | `1` | Modbus 从站地址，范围 `1..247`。 |
| 服务器 ID | `0x1001000100000001` | 临时模拟从站服务器 ID。 |
| 共享口令 | `modbus-psk-demo` | 主从站共享口令。 |
| 保持寄存器 | `10,20,30,...` | 临时模拟从站寄存器值，逗号或换行分隔，支持十进制和 `0x` 十六进制。 |
| 目标地址 | `127.0.0.1` | 主站连接临时模拟从站的地址。 |
| 客户端 ID | `0x2001000100000001` | 主站客户端 ID。 |
| 起始地址 | `0` | 要读取的保持寄存器起始地址。 |
| 读取数量 | `4` | 要读取的保持寄存器数量，范围 `1..125`。 |

## Web API

Web 界面调用 `POST /api/read`。请求体为 JSON：

```json
{
  "slave_host": "127.0.0.1",
  "slave_port": "0",
  "master_host": "127.0.0.1",
  "slave_id": "1",
  "password": "modbus-psk-demo",
  "server_id": "0x1001000100000001",
  "client_id": "0x2001000100000001",
  "start": "0",
  "quantity": "4",
  "registers": "10,20,30,40,50,60,70,80"
}
```

成功响应：

```json
{
  "ok": true,
  "result": {
    "endpoint": "127.0.0.1:41273",
    "slave_id": 1,
    "start": 0,
    "quantity": 4,
    "registers": [
      { "address": 0, "value": 10, "hex": "0x000a" }
    ],
    "master": {
      "client_id": "0x2001000100000001",
      "server_id": "0x1001000100000001",
      "mode": "aes_gcm",
      "ck": "...",
      "civ": "..."
    }
  }
}
```

失败响应：

```json
{
  "ok": false,
  "error": "错误说明"
}
```

## 测试

运行单元测试：

```bash
python3 -m unittest discover -s tests
```

测试覆盖：

- SM3 已知向量
- APDU 和数据载荷编解码
- 主从站握手和加密读寄存器
- Web 后端嵌入式从站读寄存器流程

## 常见问题

### `ModuleNotFoundError: No module named 'cryptography'`

先安装依赖：

```bash
python3 -m pip install -r requirements.txt
```

### 主站认证失败或连接报错

检查主站和从站的 `--password`、`--slave-id` 是否一致，并确认从站已经在对应 `--host` / `--port` 上监听。

### Web 页面提示读取范围超出

`起始地址 + 读取数量` 不能超过页面中配置的保持寄存器数量。

