"""模糊测试引擎 — 响应差异分析 + 参数 Fuzzing"""

import asyncio
import hashlib
import logging
import re
import time
from typing import Optional

from ..core.config import VulnForgeConfig
from ..core.target import Target
from ..scanner.scanner import Finding


# Payload 分类
PAYLOADS = {
    "special_chars": [
        "'", '"', "`", ";", "|", "&", "$(", "%00", "\n", "\r",
    ],
    "noise": [
        "FUZZ", "test", "null", "undefined", "NaN",
    ],
    "integers": [
        "0", "1", "-1", "9999999999999999999", "1e999", "-1e999",
    ],
    "booleans": [
        "true", "false", "1=1", "1=2",
        "' OR '1'='1", "' AND '1'='2",
    ],
    "path_traversal": [
        "../", "..\\", "....//", "%2e%2e%2f", "..;/..;/",
    ],
    "xss_probes": [
        "<", ">", '"<test>', "'<test>'",
    ],
    "unicode": [
        "%c0%ae%c0%ae/", "%u002e%u002e%u002f",
    ],
}


class Fuzzer:
    """响应差异分析模糊测试器"""

    def __init__(self, config: VulnForgeConfig, target: Target):
        self.config = config
        self.target = target
        self.findings: list[Finding] = []
        self.baselines: dict[str, dict] = {}  # {param_name: {"status": ..., "length": ..., "time": ..., "hash": ...}}
        self.logger = logging.getLogger(__name__)

    async def run(self, client, base_url: str, params: list[tuple[str, str]]) -> list[Finding]:
        """执行 fuzzing，返回发现的 Finding 列表"""
        self.logger.info("[Fuzzer] 开始模糊测试 — 响应差异分析")

        # 1. 发送基线请求
        await self._send_baseline(client, base_url, params)

        # 2. 对每个参数执行 fuzzing
        max_params = self.config.get("fuzzing.max_params", 10)
        payload_types = self.config.get("fuzzing.payload_types", "all")
        timeout_per_param = self.config.get("fuzzing.timeout_per_param", 30)

        # 选择 payload 类型
        if payload_types == "all":
            payload_list = []
            for group in PAYLOADS.values():
                payload_list.extend(group)
        elif payload_types == "basic":
            payload_list = (
                PAYLOADS["special_chars"] +
                PAYLOADS["noise"] +
                PAYLOADS["integers"] +
                PAYLOADS["booleans"]
            )
        else:  # "deep" or unknown
            payload_list = []
            for group in PAYLOADS.values():
                payload_list.extend(group)

        # 限制参数数量
        for param_name, param_value in params[:max_params]:
            try:
                await asyncio.wait_for(
                    self._fuzz_param(client, base_url, param_name, param_value, payload_list),
                    timeout=timeout_per_param,
                )
            except asyncio.TimeoutError:
                self.logger.warning(f"[Fuzzer] 参数 {param_name} fuzzing 超时，跳过")
            except Exception as e:
                self.logger.debug(f"[Fuzzer] 参数 {param_name} fuzzing 异常: {e}")

        self.logger.info(f"[Fuzzer] 模糊测试完成，发现 {len(self.findings)} 个异常")
        return self.findings

    async def _send_baseline(self, client, base_url: str, params: list[tuple[str, str]]):
        """发送基线请求"""
        for param_name, param_value in params:
            try:
                # 构造 URL — 直接用原始值
                sep = "&" if "?" in base_url else "?"
                url = f"{base_url}{sep}{param_name}={param_value}"
                t0 = time.time()
                resp = await client.get(url, follow_redirects=False, timeout=10)
                elapsed = time.time() - t0
                body = resp.text

                baseline = {
                    "status": resp.status_code,
                    "length": len(body),
                    "time": elapsed,
                    "hash": hashlib.md5(body.encode("utf-8", errors="replace")).hexdigest(),
                }
                self.baselines[param_name] = baseline
                self.logger.debug(f"[Fuzzer] 基线 {param_name}: {baseline}")
            except Exception as e:
                self.logger.debug(f"[Fuzzer] 基线请求失败 {param_name}={param_value}: {e}")
                # 给一个合理的默认基线
                self.baselines[param_name] = {
                    "status": 0,
                    "length": 0,
                    "time": 0,
                    "hash": "",
                }

    async def _fuzz_param(self, client, base_url: str, param_name: str, param_value: str, payload_list: list[str]):
        """对单个参数执行 fuzzing"""
        baseline = self.baselines.get(param_name)
        if baseline is None:
            return

        for payload in payload_list:
            try:
                sep = "&" if "?" in base_url else "?"
                url = f"{base_url}{sep}{param_name}={payload}"

                t0 = time.time()
                resp = await client.get(url, follow_redirects=False, timeout=10)
                elapsed = time.time() - t0
                body = resp.text

                response_info = {
                    "status": resp.status_code,
                    "length": len(body),
                    "time": elapsed,
                    "hash": hashlib.md5(body.encode("utf-8", errors="replace")).hexdigest(),
                }

                finding = self._analyze_response(baseline, response_info, payload, param_name, url, body)
                if finding:
                    self.findings.append(finding)
            except Exception as e:
                self.logger.debug(f"[Fuzzer] fuzz 请求失败 {param_name}={payload}: {e}")

    def _analyze_response(
        self,
        baseline: dict,
        response: dict,
        payload: str,
        param_name: str,
        url: str,
        body: str,
    ) -> Optional[Finding]:
        """分析响应差异，返回 Finding 或 None"""
        findings: list[Finding] = []

        # 状态码变化（基线不是 0 时才比较）
        if baseline["status"] != 0 and response["status"] != baseline["status"]:
            findings.append(Finding(
                vuln_type="fuzzing_status_change",
                url=url,
                param=param_name,
                payload=payload,
                severity="info",
                evidence=f"HTTP {baseline['status']} -> {response['status']}",
                description=f"Fuzzing 导致状态码变化: {baseline['status']} -> {response['status']} (参数: {param_name})",
            ))

        # SQL 错误匹配
        if self._has_sql_error(body):
            findings.append(Finding(
                vuln_type="fuzzing_sql_error",
                url=url,
                param=param_name,
                payload=payload,
                severity="high",
                evidence="响应正文包含 SQL 错误信息",
                description=f"Fuzzing 触发了 SQL 错误表示 (参数: {param_name})",
            ))

        # 文件路径泄露
        if self._has_path_content(body):
            findings.append(Finding(
                vuln_type="fuzzing_path_disclosure",
                url=url,
                param=param_name,
                payload=payload,
                severity="high",
                evidence="响应正文包含文件系统路径",
                description=f"Fuzzing 导致了文件路径信息泄露 (参数: {param_name})",
            ))

        # 堆栈跟踪
        if self._has_stack_trace(body):
            findings.append(Finding(
                vuln_type="fuzzing_stack_trace",
                url=url,
                param=param_name,
                payload=payload,
                severity="medium",
                evidence="响应正文包含堆栈跟踪信息",
                description=f"Fuzzing 触发了堆栈跟踪泄露 (参数: {param_name})",
            ))

        # 时间异常 — 响应时间慢于基线 3 倍以上（基线有意义才比较）
        if baseline["time"] > 0 and response["time"] > baseline["time"] * 3:
            findings.append(Finding(
                vuln_type="fuzzing_time_anomaly",
                url=url,
                param=param_name,
                payload=payload,
                severity="medium",
                evidence=f"响应时间: {baseline['time']:.3f}s -> {response['time']:.3f}s (x{response['time']/baseline['time']:.1f})",
                description=f"Fuzzing 导致响应时间显著增加 (参数: {param_name})",
            ))

        # Body 长度显著变化（>20% 增减，基线有意义才比较）
        if baseline["length"] > 0:
            length_ratio = response["length"] / baseline["length"]
            if length_ratio < 0.8 or length_ratio > 1.2:
                findings.append(Finding(
                    vuln_type="fuzzing_length_anomaly",
                    url=url,
                    param=param_name,
                    payload=payload,
                    severity="info",
                    evidence=f"Body 长度: {baseline['length']} -> {response['length']} ({length_ratio:.1%})",
                    description=f"Fuzzing 导致 Body 长度显著变化 (参数: {param_name})",
                ))

        # Body hash 与基线不同（兜底 catch-all）
        if baseline["hash"] and response["hash"] != baseline["hash"]:
            # 仅在没有其他 finding 的情况下添加 hash 变化
            if not findings:
                findings.append(Finding(
                    vuln_type="fuzzing_response_diff",
                    url=url,
                    param=param_name,
                    payload=payload,
                    severity="info",
                    evidence="响应内容 hash 与基线不同",
                    description=f"Fuzzing 导致响应内容变化 (参数: {param_name})",
                ))

        # 返回第一个发现的异常（避免重复报告）
        return findings[0] if findings else None

    def _has_sql_error(self, body: str) -> bool:
        """检查 body 是否包含 SQL 错误特征"""
        sql_patterns = [
            r"SQL syntax",
            r"mysql_fetch",
            r"MySQLSyntaxErrorException",
            r"PostgreSQL.*ERROR",
            r"SQLite.Exception",
            r"ORA-[0-9]",
            r"Unclosed quotation mark",
            r"Incorrect syntax near",
            r"Warning.*sql_exec",
            r"Division by zero",
            r"Fatal error",
        ]
        return any(re.search(p, body, re.IGNORECASE) for p in sql_patterns)

    def _has_path_content(self, body: str) -> bool:
        """检查 body 是否包含文件路径泄露"""
        path_patterns = [
            r"root:[x\*]:\d+:\d+:",
            r"dr[wx-]{9}",
            r"failed to open stream",
            r"include\(.*\)",
            r"require\(.*\)",
            r"/etc/",
            r"C:\\Windows",
        ]
        return any(re.search(p, body, re.IGNORECASE) for p in path_patterns)

    def _has_stack_trace(self, body: str) -> bool:
        """检查 body 是否包含堆栈跟踪"""
        stack_patterns = [
            r"Traceback \(most recent call last\)",
            r"at\s+\w+\.\w+\(.*\.java:\d+\)",
            r"in\s+[/\\]",
            r"File\s+\"",
            r"#0\s+\w+\(\)",
        ]
        return any(re.search(p, body, re.IGNORECASE) for p in stack_patterns)
