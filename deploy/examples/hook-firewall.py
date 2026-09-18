#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IPv8+ 外挂防火墙示例（无第三方依赖，Python 3.8+）

这是一个"外部判决者"：连接 ipv8-node 的判决钩子，对每个内层数据包
实时做出 accept/drop 判决。节点用 --hook 启动后，本脚本即生效。

用法：
    python hook-firewall.py                     # 连默认 127.0.0.1:45810
    python hook-firewall.py 127.0.0.1:45810

节点侧：
    ipv8-node --self ... --peer-addr ... --peer-ip ... --initiate --hook

判决策略（示例，随便改成你自己的）：
    1. 拦截 TCP/23（Telnet，明文协议）
    2. 每个流超过 20 包/秒 → 后续包丢弃（简易限速）
    3. 其余放行，并用 ttl_ms 把"流的首包判决"卸载给节点（5 秒内同流零 IPC）

写你自己的防火墙只需改 decide() —— 能连本地 socket 就能定义网络规则，
不需要驱动、不需要内核知识。协议见 docs/architecture.md §4。
"""

import json
import socket
import sys
import threading
import time

HOOK_ADDR = (sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1").split(":")
HOST = HOOK_ADDR[0]
PORT = int(HOOK_ADDR[1]) if len(HOOK_ADDR) > 1 else 45810

# 每流放行多少秒（流卸载 TTL）：首包判决后，节点在 TTL 内不再询问
FLOW_TTL_MS = 5000
# 简易限速窗口
RATE_WINDOW = 1.0
RATE_LIMIT = 20  # 每窗口每流最多 20 个"需要判决"的包（TTL 内不计）

# 被拦截的目标端口（想拦什么改这里）
BLOCK_DPORTS = {23}  # Telnet


class FlowMeter:
    """每流滑动窗口计数（生产环境请换成令牌桶/滑窗库）。"""

    def __init__(self):
        self._lock = threading.Lock()
        self._hits = {}  # flow -> [timestamp, ...]

    def over_limit(self, flow):
        now = time.monotonic()
        with self._lock:
            hits = [t for t in self._hits.get(flow, []) if now - t < RATE_WINDOW]
            hits.append(now)
            self._hits[flow] = hits
            # 惰性清理
            if len(self._hits) > 4096:
                self._hits = {
                    f: v for f, v in self._hits.items()
                    if v and now - v[-1] < RATE_WINDOW
                }
            return len(hits) > RATE_LIMIT


def decide(event, meter):
    """返回 (action, ttl_ms)。改这个函数就是改防火墙。"""
    proto = event.get("proto")
    dport = event.get("dport", 0)
    flow = event.get("flow", "")

    # 规则 1：拦截危险端口（硬丢弃，不卸载——保持随时可改）
    if proto == "tcp" and dport in BLOCK_DPORTS:
        return "drop", 0

    # 规则 2：每流限速
    if meter.over_limit(flow):
        return "drop", 0

    # 默认放行，整流卸载 5 秒（节点缓存，后续包不再问，性能无损）
    return "accept", FLOW_TTL_MS


def main():
    s = socket.create_connection((HOST, PORT), timeout=5)
    f = s.makefile("rwb", buffering=0)

    hello = {"type": "hello", "mode": "decision", "name": "demo-py-firewall", "version": 1}
    f.write((json.dumps(hello) + "\n").encode())

    ack = json.loads(f.readline())
    if not ack.get("ok"):
        print(f"[!] 被拒绝/降级：{ack.get('reason')}（已有判决者占用？）", file=sys.stderr)
        sys.exit(1)
    print(f"[+] 已接管判决：{HOST}:{PORT}（{ack.get('server')}），Ctrl+C 退出")

    meter = FlowMeter()
    decided = 0
    try:
        for line in f:
            event = json.loads(line)
            if event.get("type") != "event":
                continue
            action, ttl = decide(event, meter)
            verdict = {
                "type": "verdict",
                "id": event["id"],
                "action": action,
                "ttl_ms": ttl,
            }
            f.write((json.dumps(verdict) + "\n").encode())
            decided += 1
            if decided % 50 == 0 or action == "drop":
                print(
                    f"[{event.get('direction')}] {event.get('src')}:{event.get('sport')}"
                    f" -> {event.get('dst')}:{event.get('dport')} "
                    f"{event.get('proto')} => {action.upper()}"
                )
    except (KeyboardInterrupt, ConnectionError, OSError):
        pass
    finally:
        print(f"[i] 共判决 {decided} 个事件，退出")
        s.close()


if __name__ == "__main__":
    main()
