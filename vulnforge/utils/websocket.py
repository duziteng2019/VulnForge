"""WebSocket 安全测试模块 — 连接测试 + 消息 fuzzing"""

import asyncio
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# WebSocket fuzzing payloads
WS_PAYLOADS = {
    "injection": [
        "' OR '1'='1",
        "<script>alert(1)</script>",
        "../../../etc/passwd",
        "${7*7}",
        "{{7*7}}",
    ],
    "large_payload": ["A" * 10000, "A" * 100000],
    "protocol_break": [
        "\x00\x00\x00\x00",
        "\xff\xff\xff\xff",
        "\r\n\r\n",
    ],
    "json_parse": [
        "null",
        "undefined",
        "{",
        "}",
        '{"a": "b"',
        "<!DOCTYPE foo>",
    ],
    "control_chars": [
        "\x00",
        "\x01\x02\x03",
        "\x1b[2J",
        "\x1b",
    ],
}


class WebSocketTester:
    """WebSocket 安全测试器

    检测:
    - WebSocket 连接建立（是否有认证）
    - 消息注入（SQL/XSS/命令注入）
    - 协议异常处理
    - 超大消息处理
    - JSON 解析错误
    - 敏感信息泄露
    """

    def __init__(self, config, target, scan_id: str = ""):
        self.config = config
        self.target = target
        self.scan_id = scan_id
        self.findings = []
        self.logger = logging.getLogger(__name__)

    async def run(self, endpoints: list[str]) -> list[dict]:
        """对发现的 WebSocket 端点执行安全测试

        Args:
            endpoints: WebSocket URL 列表 (wss:// 或 ws://)

        Returns:
            漏洞发现列表
        """
        if not endpoints:
            return []

        for ep in endpoints:
            self.logger.info("WebSocket 测试: %s", ep)
            await self._test_endpoint(ep)

        return self.findings

    async def _test_endpoint(self, endpoint: str) -> None:
        """测试单个 WebSocket 端点"""
        try:
            import websockets
        except ImportError:
            self.logger.warning("websockets 库未安装，跳过 WebSocket 测试 (pip install websockets)")
            return

        # 1. 基本连接测试
        try:
            async with websockets.connect(endpoint, timeout=10) as ws:
                self.logger.debug("WebSocket 连接成功: %s", endpoint)
                self.findings.append({
                    "vuln_type": "websocket/exposed",
                    "url": endpoint,
                    "severity": "info",
                    "evidence": "WebSocket 端点可公开访问",
                    "description": f"WebSocket 端点可匿名连接: {endpoint}",
                })

                # 2. 消息 fuzzing
                for category, payloads in WS_PAYLOADS.items():
                    for payload in payloads:
                        try:
                            await ws.send(payload)
                            resp = await asyncio.wait_for(ws.recv(), timeout=5)

                            # 分析响应
                            finding = self._analyze_response(endpoint, category, payload, resp)
                            if finding:
                                self.findings.append(finding)
                        except asyncio.TimeoutError:
                            pass
                        except Exception as e:
                            # 连接断开 = 异常 handled
                            self.logger.debug("WebSocket 消息异常: %s", e)
                            break

        except Exception as e:
            self.logger.debug("WebSocket 连接失败 %s: %s", endpoint, e)

    def _analyze_response(self, endpoint: str, category: str, payload: str, response) -> Optional[dict]:
        """分析 WebSocket 响应"""
        resp_str = str(response) if response else ""

        # SQL 错误检测
        sql_patterns = ["SQL syntax", "mysql_fetch", "ORA-", "Unclosed quotation"]
        for p in sql_patterns:
            if p.lower() in resp_str.lower():
                return {
                    "vuln_type": "websocket/sql_injection",
                    "url": endpoint,
                    "severity": "high",
                    "evidence": f"SQL 错误: {p}",
                    "description": f"WebSocket 消息存在 SQL 注入: {payload[:50]}",
                }

        # XSS / 反射检测
        if payload in resp_str and "<" in payload:
            return {
                "vuln_type": "websocket/xss",
                "url": endpoint,
                "severity": "medium",
                "evidence": "payload 反射在响应中",
                "description": f"WebSocket 消息反射 XSS: {payload[:50]}",
            }

        # 敏感信息泄露
        info_patterns = ["password", "secret", "token", "api_key", "internal"]
        for p in info_patterns:
            if p.lower() in resp_str.lower():
                return {
                    "vuln_type": "websocket/info_leak",
                    "url": endpoint,
                    "severity": "medium",
                    "evidence": f"响应包含 '{p}'",
                    "description": "WebSocket 响应可能泄露敏感信息",
                }

        # 错误/异常信息
        error_patterns = ["traceback", "exception", "error", "warning", "fatal"]
        for p in error_patterns:
            if p.lower() in resp_str.lower():
                return {
                    "vuln_type": "websocket/error_leak",
                    "url": endpoint,
                    "severity": "medium",
                    "evidence": f"错误信息: {resp_str[:100]}",
                    "description": "WebSocket 响应包含错误/异常信息",
                }

        return None
