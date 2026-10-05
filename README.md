# dnslookup

不用 `dig` 也能查 DNS：纯标准库手写的 DNS 客户端。自己用 `struct` 拼查询包、自己解析响应（含域名压缩指针），零第三方依赖。

## 安装

零依赖，Python 3.10+ 直接跑：

```bash
cd dnslookup
python3 -m dnslookup example.com
```

## 用法

```bash
# 查 A 记录（默认）
python3 -m dnslookup example.com

# 查其他类型
python3 -m dnslookup example.com --type MX
python3 -m dnslookup example.com -t TXT
python3 -m dnslookup example.com -t AAAA

# 指定 DNS 服务器 / 端口 / 超时
python3 -m dnslookup example.com --server 1.1.1.1
python3 -m dnslookup example.com --server 127.0.0.1 --port 15353

# 显示耗时 / JSON 输出
python3 -m dnslookup example.com --time
python3 -m dnslookup example.com --json
```

示例输出：

```
===== DNS 查询：example.com（MX）=====
服务器：8.8.8.8:53（UDP）　响应码：NOERROR
  example.com  300s  MX  10 mail.example.com
```

NXDOMAIN 会给干净的中文提示并返回 exit 1（脚本里可直接判断）。

### `--tcp`：走 DNS over TCP

有些网络/沙箱环境会拦截 UDP 53（直连发包直接 `Operation not permitted`），这时加 `--tcp`：

```bash
python3 -m dnslookup example.com --tcp
```

走 RFC 7766 的 DNS over TCP（2 字节长度前缀），查询包字节和解析逻辑与 UDP 完全一致。

## 支持的查询类型

`A` `AAAA` `MX` `TXT` `CNAME` `NS` `SOA` `PTR`

响应解析处理了：域名压缩指针（含多级跳转与循环保护）、多应答记录、RCODE（`NXDOMAIN` 等中文提示）、TC 截断标志提醒。

## 退出码

| 退出码 | 含义 |
|---|---|
| 0 | 查询成功（即使 0 条应答） |
| 1 | NXDOMAIN / 网络错误 / 超时 / 响应解析失败 |
| 2 | 用法错误（缺域名、不支持的类型） |

## 诚实说明

- **只实现 UDP 和 TCP 查询**：DoT（853 端口）/DoH（HTTPS）不在范围内。
- **不做 DNSSEC 校验**：拿到的记录不验证签名，别拿它做安全决策。
- **默认不校验、只解析**：和 `dig +short` 一样，相信你指定的服务器。
- 响应包按 4096 字节接收；超大响应走 TCP 更稳。
- 超时默认 5 秒，可用 `--timeout` 调整。

## 已知局限

- 查询包只带一个问题（QDCOUNT=1），这是最常见的用法。
- 名字压缩指针最多跟随 32 跳，防恶意循环包。
- 解析的是服务器返回的原文；`CNAME` 等不会自动追下去再查一遍（`dig` 默认也不追）。

## License

MIT，Copyright (c) 2026 ljiang9
