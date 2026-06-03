# Modbus 串行链路内生安全原生扩展协议

本目录整合了三个独立参考实现：

- `protocols-ECC`：基于 ECC PKI 公钥证书的 Modbus 串行链路通信安全扩展协议。
- `protocols-psw`：基于口令或预共享密钥的 Modbus 串行链路安全协议。
- `protocols-mpq`：基于后量子混合签名 PKI 公钥证书的 Modbus 串行链路安全协议。

根目录提供统一启动器 `unified_server.py`。它会同时启动三个子项目的 Web UI，并提供一个带三个标签页的统一入口。

If a real UART interface is used, the socket initialized here is only formal and not actually used. Every frame read and sent is completed on UART.

## 安装依赖

```bash
python3 -m pip install -r requirements.txt
```

## 一命令启动

在根目录执行：

```bash
python3 unified_server.py
```

然后打开：

```text
http://127.0.0.1:18000/
```

默认端口：

| 服务 | 地址 |
| --- | --- |
| 统一 UI | `http://127.0.0.1:18000/` |
| ECC PKI 子项目 | `http://127.0.0.1:18080/` |
| 口令/预共享密钥子项目 | `http://127.0.0.1:18081/` |
| 后量子混合签名 PKI 子项目 | `http://127.0.0.1:18082/` |

统一 UI 中的三个标签页会分别打开这三个子项目页面。

## 参数

```bash
python3 unified_server.py \
  --host 127.0.0.1 \
  --port 18000 \
  --ecc-port 18080 \
  --psw-port 18081 \
  --mpq-port 18082
```

如果某个子项目默认端口已被占用，启动器会自动为该子项目选择一个可用端口，并在终端输出实际地址。

如需让同一网络内其他机器访问，可监听所有网卡：

```bash
python3 unified_server.py --host 0.0.0.0
```
