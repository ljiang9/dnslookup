#!/usr/bin/env python3
"""dnslookup：不用 dig 也能查 DNS 的小工具。

纯标准库实现的手写 DNS 客户端：用 struct 拼 DNS 查询包、
自己解析响应（含域名压缩指针），不依赖 dnspython 等第三方库。
"""
import argparse
import json
import random
import socket
import struct
import sys
import time

# 查询类型
QTYPES = {
    "A": 1, "AAAA": 28, "MX": 15, "TXT": 16,
    "CNAME": 5, "NS": 2, "SOA": 6, "PTR": 12,
}
QTYPES_R = {v: k for k, v in QTYPES.items()}

# 响应码
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
          4: "NOTIMP", 5: "REFUSED"}


def encode_name(name):
    """把域名编码为 DNS label 序列：www.example.com -> b'\\x03www\\x07example\\x03com\\x00'"""
    labels = []
    for part in name.rstrip(".").split("."):
        b = part.encode("utf-8")
        if len(b) > 63:
            raise ValueError(f"域名标签过长：{part}")
        labels.append(bytes([len(b)]) + b)
    return b"".join(labels) + b"\x00"


def decode_name(msg, offset):
    """从响应包 offset 处解码域名，处理 0xC0 压缩指针。返回 (域名, 新 offset)。"""
    labels = []
    jumped = False
    new_offset = offset
    seen = 0
    while True:
        if offset >= len(msg):
            raise ValueError("响应包被截断：域名解码越界")
        length = msg[offset]
        if length & 0xC0 == 0xC0:  # 压缩指针
            if offset + 1 >= len(msg):
                raise ValueError("响应包被截断：压缩指针越界")
            if not jumped:
                new_offset = offset + 2
            offset = struct.unpack(">H", msg[offset:offset + 2])[0] & 0x3FFF
            jumped = True
            seen += 1
            if seen > 32:
                raise ValueError("域名压缩指针循环过多")
            continue
        if length == 0:
            if not jumped:
                new_offset = offset + 1
            break
        if length & 0xC0:
            raise ValueError("非法的域名 label 长度")
        offset += 1
        if offset + length > len(msg):
            raise ValueError("响应包被截断：label 越界")
        labels.append(msg[offset:offset + length].decode("utf-8", errors="replace"))
        offset += length
    return ".".join(labels), new_offset


def build_query(name, qtype):
    """构造 DNS 查询包。返回 (包字节, 事务 ID)。"""
    txid = random.randint(0, 65535)
    header = struct.pack(">HHHHHH",
                         txid,      # ID
                         0x0100,    # flags: 递归查询
                         1,         # QDCOUNT
                         0, 0, 0)   # AN/NS/ARCOUNT
    question = encode_name(name) + struct.pack(">HH", qtype, 1)  # QTYPE, QCLASS=IN
    return header + question, txid


def parse_rdata(msg, offset, rdlen, rtype):
    """解析 RDATA。返回人类可读的字符串。"""
    raw = msg[offset:offset + rdlen]
    if rtype == 1 and rdlen == 4:  # A
        return socket.inet_ntoa(raw)
    if rtype == 28 and rdlen == 16:  # AAAA
        return socket.inet_ntop(socket.AF_INET6, raw)
    if rtype == 15 and rdlen >= 2:  # MX: preference + exchange
        pref = struct.unpack(">H", raw[:2])[0]
        exchange, _ = decode_name(msg, offset + 2)
        return f"{pref} {exchange}"
    if rtype == 16:  # TXT: 一个或多个 length-prefixed 字符串
        parts, i = [], 0
        while i < rdlen:
            ln = raw[i]
            i += 1
            parts.append(raw[i:i + ln].decode("utf-8", errors="replace"))
            i += ln
        return " ".join(f'"{p}"' for p in parts)
    if rtype in (2, 5, 12):  # NS / CNAME / PTR: 域名
        name, _ = decode_name(msg, offset)
        return name
    if rtype == 6:  # SOA: mname rname + 5 个 uint32
        mname, off = decode_name(msg, offset)
        rname, off = decode_name(msg, off)
        serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", msg[off:off + 20])
        return (f"{mname} {rname} serial={serial} refresh={refresh} "
                f"retry={retry} expire={expire} minimum={minimum}")
    return raw.hex()


def query(name, qtype, server, port=53, timeout=5, use_tcp=False):
    """发一次 DNS 查询，返回 (answers, rcode, flags, elapsed_ms)。

    use_tcp=True 时走 DNS over TCP（RFC 7766，2 字节长度前缀），
    适合 UDP 被防火墙拦截的环境。
    """
    packet, txid = build_query(name, qtype)
    start = time.monotonic()
    if use_tcp:
        resp = _query_tcp(packet, server, port, timeout)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (server, port))
            resp, _ = sock.recvfrom(4096)
        finally:
            sock.close()
    elapsed = (time.monotonic() - start) * 1000

    if len(resp) < 12:
        raise ValueError("响应包太短（<12 字节），不是合法 DNS 响应")
    rid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", resp[:12])
    if rid != txid:
        raise ValueError("事务 ID 不匹配，可能是串扰包")
    rcode = flags & 0x000F
    truncated = bool(flags & 0x0200)
    offset = 12
    # 跳过问题区
    for _ in range(qd):
        _, offset = decode_name(resp, offset)
        offset += 4
    # 解析应答区
    answers = []
    for _ in range(an):
        rr_name, offset = decode_name(resp, offset)
        if offset + 10 > len(resp):
            raise ValueError("响应包被截断：资源记录头越界")
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", resp[offset:offset + 10])
        offset += 10
        if offset + rdlen > len(resp):
            raise ValueError("响应包被截断：RDATA 越界")
        answers.append({
            "name": rr_name,
            "type": QTYPES_R.get(rtype, f"TYPE{rtype}"),
            "ttl": ttl,
            "data": parse_rdata(resp, offset, rdlen, rtype),
        })
        offset += rdlen
    return answers, rcode, {"truncated": truncated, "authoritative": bool(flags & 0x0400)}, elapsed


def _query_tcp(packet, server, port, timeout):
    """TCP 发送 DNS 查询：先写 2 字节长度，再读 2 字节长度 + 响应体。"""
    sock = socket.create_connection((server, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(struct.pack(">H", len(packet)) + packet)
        hdr = _recv_exact(sock, 2)
        (resp_len,) = struct.unpack(">H", hdr)
        if resp_len < 12 or resp_len > 65535:
            raise ValueError(f"TCP 响应长度异常：{resp_len}")
        return _recv_exact(sock, resp_len)
    finally:
        sock.close()


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ValueError("TCP 连接被对端提前关闭")
        buf += chunk
    return buf


def cmd_main(argv=None):
    ap = argparse.ArgumentParser(
        prog="dnslookup",
        description="不用 dig 也能查 DNS：纯标准库手写 DNS 客户端")
    ap.add_argument("domain", nargs="?", help="要查询的域名（如 example.com）")
    ap.add_argument("--type", "-t", default="A", dest="qtype",
                    help="查询类型：A/AAAA/MX/TXT/CNAME/NS/SOA（默认 A）")
    ap.add_argument("--server", "-s", default="8.8.8.8",
                    help="DNS 服务器（默认 8.8.8.8）")
    ap.add_argument("--port", type=int, default=53, help="DNS 端口（默认 53）")
    ap.add_argument("--timeout", type=int, default=5, help="超时秒数（默认 5）")
    ap.add_argument("--json", action="store_true", help="JSON 输出")
    ap.add_argument("--time", action="store_true", help="显示查询耗时")
    ap.add_argument("--tcp", action="store_true",
                    help="走 DNS over TCP（UDP 被拦截时用，如某些沙箱/防火墙环境）")
    args = ap.parse_args(argv)

    if not args.domain:
        ap.print_usage(sys.stderr)
        print("error: 请指定要查询的域名", file=sys.stderr)
        return 2
    qtype_name = args.qtype.upper()
    if qtype_name not in QTYPES:
        print(f"error: 不支持的查询类型：{args.qtype}（支持 {', '.join(QTYPES)}）",
              file=sys.stderr)
        return 2

    try:
        answers, rcode, flags, elapsed = query(
            args.domain, QTYPES[qtype_name], args.server,
            port=args.port, timeout=args.timeout, use_tcp=args.tcp)
    except socket.timeout:
        print(f"error: 查询超时（{args.server}:{args.port} {args.timeout}s 无响应）",
              file=sys.stderr)
        return 1
    except OSError as e:
        print(f"error: 网络错误：{e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"error: 响应解析失败：{e}", file=sys.stderr)
        return 1

    result = {
        "domain": args.domain,
        "type": qtype_name,
        "server": args.server,
        "rcode": RCODES.get(rcode, f"RCODE{rcode}"),
        "truncated": flags["truncated"],
        "answers": answers,
    }
    if args.time:
        result["elapsed_ms"] = round(elapsed, 1)

    if rcode == 3:
        msg = f"NXDOMAIN：域名 {args.domain} 不存在"
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print(msg)
        return 1

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"===== DNS 查询：{args.domain}（{qtype_name}）=====")
        print(f"服务器：{args.server}:{args.port}（{'TCP' if args.tcp else 'UDP'}）　响应码：{result['rcode']}")
        if flags["truncated"]:
            if args.tcp:
                print("⚠️ 响应被截断（TC 标志）：结果可能不完整")
            else:
                print("⚠️ 响应被截断（TC 标志）：结果可能不完整，建议加 --tcp 改走 TCP 查询")
        if not answers:
            print("（无应答记录）")
        for a in answers:
            print(f"  {a['name']}  {a['ttl']}s  {a['type']}  {a['data']}")
        if args.time:
            print(f"查询耗时：{elapsed:.1f} ms")
    return 0


def main():
    sys.exit(cmd_main())


if __name__ == "__main__":
    main()
