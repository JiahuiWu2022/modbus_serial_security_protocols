# Modbus 串行链路安全扩展 6.4 参考实现

本项目实现《Modbus串行链路通信协议安全扩展技术要求》6.4 节描述的“基于后量子混合签名 PKI 公钥证书”的主从站参考端点，并提供一个单页 Web UI。

说明：当前 Python 依赖没有生产级 ML-KEM-768 / ML-DSA-44 实现，6.4 模块使用演示 KEM 与 Ed25519 演示证书链来保持 APDU 字段、密文长度、共享密钥长度和派生公式与文档一致。生产环境需要替换为合规的 ML-KEM/ML-DSA/X.509/HSM 实现。

说明：6.4 模块使用 `pqcrypto` 提供的 ML-KEM-768 完成 `KEM_C` / `KEM_BC` 封装与解封装，使用 ML-DSA-44 完成根/品牌/设备证书链签名验证。当前证书容器仍是便于演示和测试的 JSON 格式，内置根/品牌测试密钥只适合本地互通；生产环境需要替换为合规的 X.509/HSM 或设备安全存储实现。

If a real UART interface is used in modbus_security_pq.by, the socket initialized here is only formal and not actually used. Every frame read and sent is completed on UART.

## 实现内容

- `ss_open_req` / `ss_open_cnf`
- `ss_data_req` / `ss_data_cnf`
- RTU 功能码 `0x00` 承载安全 APDU
- 从站发起证书链交换
- `KEM_C` / `KEM_BC` / `mode` 参数交换
- `AKH` / `AKM` 认证密钥校验
- `KEMSK`、`KEMSK_B`、`CK/CIV`、`BCK/BCIV` 派生
- AES-GCM 内容加密后的 `ss_data_send`
- 示例 Modbus `0x03` 保持寄存器读取
- 单页 Web UI：参数校验、启动命令生成、读取视图和 6.4 消息序列

## 项目结构

```text
.
├── master_server.py              # 6.4 主站命令行端点
├── slave_server.py               # 6.4 从站命令行端点
├── modbus_security_pq.py         # 6.4 协议编解码、证书/KEM演示、握手和加解密
├── web_frontend.py               # 单页 Web UI 静态服务器
├── web/
│   └── index.html                # 6.4 单页主页，内嵌 CSS/JS
├── tests/
│   └── test_modbus_security_pq.py
├── requirements.txt
└── Modbus串行链路通信协议安全扩展技术要求.docx
```

## 环境要求

- Python 3.10 或更新版本
- 可创建本地 TCP/socket 连接
- Python 依赖：`cryptography>=42`

安装依赖：

```bash
python3 -m pip install -r requirements.txt
```

## 命令行启动

先启动 6.4 从站：

```bash
python3 slave_server.py --host 127.0.0.1 --port 15020
```

另开一个终端启动主站并读取保持寄存器：

```bash
python3 master_server.py --host 127.0.0.1 --port 15020 --start 0 --quantity 4
```

一次性从站示例：

```bash
python3 slave_server.py --host 127.0.0.1 --port 15020 --once
```

## Web UI

启动单页 Web UI：

```bash
python3 web_frontend.py --host 127.0.0.1 --port 8080
```

打开：

```text
http://127.0.0.1:8080
```

页面可以配置主从站参数、生成主站/从站启动命令、校验寄存器读取范围，并展示 6.4 握手消息序列。

## 参数说明

`master_server.py` 和 `slave_server.py` 都支持：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--host` | `127.0.0.1` | TCP 监听或连接地址。 |
| `--port` | `15020` | TCP 监听或连接端口。 |
| `--slave-id` | `1` | Modbus 从站地址，范围 `1..247`，支持十进制或 `0x` 十六进制。 |

主站额外参数：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--client-id` | `0x2001000100000001` | 主站客户端 ID，支持十进制或 `0x` 十六进制。 |
| `--start` | `0` | 保持寄存器起始地址。 |
| `--quantity` | `4` | 读取寄存器数量，范围 `1..125`。 |

从站额外参数：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--server-id` | `0x1001000100000001` | 从站服务器 ID，支持十进制或 `0x` 十六进制。 |
| `--registers` | `64` | 示例保持寄存器数量。寄存器值按 `(索引 + 1) * 10` 自动生成。 |
| `--once` | 关闭 | 处理一个主站连接后退出。 |

## 测试

运行单元测试：

```bash
python3 -m unittest discover -s tests
```

测试覆盖：

- SM3 已知向量
- APDU 和数据载荷编解码
- 6.4 后量子混合 PKI 主从站握手和加密读寄存器



