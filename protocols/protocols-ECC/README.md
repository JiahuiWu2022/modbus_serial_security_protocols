# Modbus 串行链路安全扩展 6.2 参考实现

这是根据《Modbus串行链路通信协议安全扩展技术要求》第 6.2 节实现的主站/从站参考原型，包含安全协议实现、主从站服务和前端 UI 控制台。

推荐使用“一命令启动 UI”模式：只在命令行启动 UI 控制台，然后在页面内完成 PKI 准备、从站启动、主站启动和寄存器读写。

## 1. 环境准备

进入项目目录：

```bash
cd /home/protocols
```

确认 Python 可用：

```bash
python3 --version
```

安装依赖：

```bash
pip install -r requirements.txt
```

当前实现依赖 `cryptography`。如果环境已经预装该库，可跳过安装。

## 2. 一命令启动 UI

启动 UI 控制台：

```bash
python3 -m secure_modbus.ui_server --host 127.0.0.1 --port 18080
```

打开浏览器访问：

```text
http://127.0.0.1:18080/
```

启动参数：

```text
--host：UI 服务监听 IP 地址，例如 127.0.0.1 或 0.0.0.0
--port：UI 服务监听端口，例如 18080
```

如果需要让同一网络内其他机器访问 UI，可监听所有网卡：

```bash
python3 -m secure_modbus.ui_server --host 0.0.0.0 --port 18080
```

然后使用服务器实际 IP 访问：

```text
http://<服务器IP>:18080/
```

页面包含以下操作区：

- 准备工作：输入 PKI 目录、状态目录，点击“生成演示 PKI”。
- 启动从站：输入监听地址、监听端口、从站地址，点击“启动从站”。
- 启动主站：输入目标从站地址、端口和从站号，点击“启动主站”。
- 寄存器操作：执行读保持寄存器、写单寄存器。
- 安全链路参数：展示主从站 ID、功能码、认证上下文、握手阶段。
- 密钥与计数器输出：展示 `AKH/DHSK/SAK/SEK/CK/CIV/BCK/BCIV` 的截断摘要，以及 SAC 和内容 PDU 计数器。
- 最近结果：展示最近一次读写操作结果。
- 从站日志：展示从站进程输出。
- 操作事件：展示 UI 内执行的准备、启动和读写事件。

默认页面参数：

```text
PKI 目录：demo_pki
状态目录：.secure_modbus_state
从站监听地址：127.0.0.1
从站监听端口：15020
从站地址：1
主站目标从站：127.0.0.1:15020 / 1
```

## 3. UI 内操作顺序

### 3.1 生成演示 PKI

在“准备工作”区域点击：

```text
生成演示 PKI
```

生成后会显示演示身份：

```text
CLIENT_ID = 0102030405060708
SERVER_ID = 1112131415161718
```

生成目录结构：

```text
demo_pki/
  root_cert.json
  client/
    private_key.pem
    device_cert.json
    brand_cert.json
  server/
    private_key.pem
    device_cert.json
    brand_cert.json
```

### 3.2 启动从站

在“启动从站”区域确认参数：

```text
监听地址：127.0.0.1
监听端口：15020
从站地址：1
```

点击：

```text
启动从站
```

页面右侧“运行状态”会显示从站 PID，“从站日志”会显示监听日志。

### 3.3 启动主站

在“启动主站”区域确认参数：

```text
从站地址：127.0.0.1
从站端口：15020
目标从站号：1
```

点击：

```text
启动主站
```

此时主站对象已创建，但安全握手通常会在第一次读写操作时触发。

### 3.4 读取保持寄存器

在“寄存器操作”区域填写：

```text
读起始地址：0
读取数量：4
```

点击：

```text
读取
```

首次读取会触发完整安全链路：

```text
从站 ss_open_req
主站 ss_open_cnf
证书认证或 AKH 重新认证
SAC 初始化
内容密钥 CK/BCK 更新
ss_data_send 加密传输 Modbus PDU
```

完成后页面会展示：

- 读出的寄存器值
- `CLIENT_ID` 与 `SERVER_ID`
- 四个安全阶段是否完成
- 密钥摘要和计数器
- 从站收到的加密 PDU 解密后的日志

### 3.5 写单寄存器

在“寄存器操作”区域填写：

```text
写入地址：3
写入值：2468
```

点击：

```text
写入
```

写入成功后页面会自动回读附近寄存器，并在“最近结果”和“操作事件”中显示结果。

## 4. UI 控制接口

UI 页面调用以下本地接口：

```text
GET  /
GET  /api/status
POST /api/pki/init?pki=demo_pki
POST /api/slave/start?pki=demo_pki&state=.secure_modbus_state&host=127.0.0.1&port=15020&address=1
POST /api/slave/stop
POST /api/master/start?pki=demo_pki&state=.secure_modbus_state&slave_host=127.0.0.1&slave_port=15020&slave_address=1
POST /api/master/stop
GET  /api/read?start=0&qty=4
POST /api/write?register=3&value=2468
```

示例：

```bash
curl -X POST 'http://127.0.0.1:18080/api/pki/init?pki=demo_pki'
curl -X POST 'http://127.0.0.1:18080/api/slave/start?pki=demo_pki&state=.secure_modbus_state&host=127.0.0.1&port=15020&address=1'
curl -X POST 'http://127.0.0.1:18080/api/master/start?pki=demo_pki&state=.secure_modbus_state&slave_host=127.0.0.1&slave_port=15020&slave_address=1'
curl 'http://127.0.0.1:18080/api/read?start=0&qty=4'
curl -X POST 'http://127.0.0.1:18080/api/write?register=3&value=2468'
```

## 5. 手工命令模式

如果不使用一命令 UI，也可以分别启动主从站。

### 5.1 生成演示 PKI

```bash
python3 -m secure_modbus.pki --out demo_pki
```

### 5.2 启动从站服务

从站负责监听 TCP 连接，按 6.2 流程发起认证、SAC 建立、内容密钥更新，并处理加密 Modbus PDU。

```bash
python3 -m secure_modbus.slave_server \
  --pki demo_pki \
  --port 15020 \
  --address 1
```

默认参数：

```text
监听地址：127.0.0.1
监听端口：15020
Modbus 从站地址：1
```

### 5.3 启动主站服务和前端 UI

主站服务连接从站，并提供 HTTP API 和前端控制台。

```bash
python3 -m secure_modbus.master_server \
  --pki demo_pki \
  --slave-port 15020 \
  --http-port 18080
```

启动后打开：

```text
http://127.0.0.1:18080/
```

前端 UI 展示：

- 主站 `CLIENT_ID`
- 从站 `SERVER_ID`
- 从站 TCP 地址、Modbus 地址、功能码 `0x00`
- 证书认证或重新认证状态
- SAC 通道建立状态
- 内容密钥更新状态
- 加密 Modbus PDU 状态
- `AKH`、`DHSK`、`SAK`、`SEK`、`CK`、`CIV`、`BCK`、`BCIV` 的截断摘要
- SAC 发送/接收计数器
- 内容 PDU 发送计数器
- 读写寄存器操作日志

## 6. 手工模式前端操作

### 读取保持寄存器

在 UI 中填写：

```text
起始地址：0
数量：4
```

点击“读取”。

### 写单寄存器

在 UI 中填写：

```text
写入地址：2
写入值：4321
```

点击“写入”。写入成功后页面会自动回读附近寄存器。

## 7. 手工模式 HTTP API 验证

查看服务健康状态：

```bash
curl 'http://127.0.0.1:18080/health'
```

查看安全链路状态：

```bash
curl 'http://127.0.0.1:18080/status'
```

读取保持寄存器：

```bash
curl 'http://127.0.0.1:18080/read?start=0&qty=4'
```

写单寄存器：

```bash
curl -X POST 'http://127.0.0.1:18080/write?register=2&value=4321'
```

示例响应：

```json
{"start": 0, "quantity": 4, "values": [0, 1, 4321, 3]}
```

## 8. 认证上下文

认证上下文默认保存在：

```text
.secure_modbus_state/
```

主站和从站在首次绑定后会保存 `DHSK`、`AKH/AKM`、对端 ID 和加密模式。后续重新启动时，如果认证上下文有效，会优先走 AKH 重新认证路径，减少证书认证和 ECDH 交换步骤。

如需重新执行首次证书认证，可删除该目录后重启主从站：

```bash
rm -rf .secure_modbus_state
```

## 9. 功能范围

已实现：

- Modbus RTU 外层帧封装和 CRC16 校验
- 功能码 `0x00` 安全扩展 APDU
- ECC PKI 演示证书链
- ECDSA 证书签名验证
- ECDH 主密钥协商
- `RM`、`RH` 校验
- `AKH/AKM` 认证密钥验证
- SAC 通道认证与加密封装
- 内容密钥 `CK/CIV`、广播内容密钥 `BCK/BCIV` 更新
- 加密传输原始 Modbus PDU
- `0x03` 读保持寄存器
- `0x06` 写单寄存器
- 前端 UI 状态展示和寄存器操作

说明：文档要求的 SM2/SM3/SM4、AES-XCBC-MAC、HSM、TEE 和硬件安全存储需要专用国密库和硬件环境。本项目中的算法层使用 `cryptography` 提供的 P-256 ECDSA/ECDH、SHA-256/HKDF、AES-CBC/HMAC 和 AES-GCM 作为可运行参考实现，后续可在 `secure_modbus/crypto.py` 中替换为国密实现。

## 10. 常见问题

### 端口被占用

如果 `15020` 或 `18080` 已被占用，可换端口：

```bash
python3 -m secure_modbus.ui_server --host 127.0.0.1 --port 18081
```

然后访问：

```text
http://127.0.0.1:18081/
```

手工模式下也可分别换主从站端口：

```bash
python3 -m secure_modbus.slave_server --pki demo_pki --port 15021 --address 1
python3 -m secure_modbus.master_server --pki demo_pki --slave-port 15021 --http-port 18081
```

### 主站连接失败

在一命令 UI 中，确认从站已经启动，并且主站目标从站端口与从站监听端口一致。第一次读取或写入会触发安全连接和握手。

手工模式可检查：

```bash
curl 'http://127.0.0.1:18080/status'
```

如果状态中 `connected` 为 `false`，在 UI 中执行一次读取操作会触发连接和握手。若仍失败，确认从站端口、PKI 目录和从站地址一致。

### 证书或认证失败

重新生成演示 PKI 并清理认证上下文：

```bash
rm -rf demo_pki .secure_modbus_state
python3 -m secure_modbus.pki --out demo_pki
```

然后按顺序重启从站和主站，或在一命令 UI 中重新生成 PKI 并重新启动主从站。
