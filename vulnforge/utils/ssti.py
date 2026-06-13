"""SSTI (Server-Side Template Injection) 检测器

支持的模板引擎:
  - Jinja2 / Twig (Python/PHP): {{7*7}} → 49
  - Freemarker (Java): ${7*7} → 49
  - Velocity (Java): #set($x=7*7)$x → 49
  - Smarty (PHP): {$smarty.version} → 版本号
  - Mako (Python): ${7*7} → 49
  - ERB (Ruby): <%= 7*7 %> → 49
"""

import logging
from typing import Optional

import httpx


class SSTITester:
    """SSTI 模板注入检测器"""

    # (payload, engine_name, response_check)
    PAYLOADS = [
        ("{{7*7}}", "Jinja2/Twig", lambda r: "49" in r),
        ("${7*7}", "Mako/FreeMarker", lambda r: "49" in r),
        ("${{7*7}}", "Freemarker", lambda r: "49" in r),
        ("#{7*7}", "Ruby/ERB", lambda r: "49" in r),
        ("{{config}}", "Jinja2 Config", lambda r: "SECRET" in r or "DEBUG" in r),
        (
            "{{self._TemplateReference__context}}",
            "Jinja2 Context",
            lambda r: "__builtins__" in r,
        ),
        (
            "#set($x=7*7)$x",
            "Velocity",
            lambda r: "49" in r,
        ),
        (
            "{$smarty.version}",
            "Smarty",
            lambda r: any(kw in r for kw in ["Smarty", "smarty", "1.", "2.", "3."]),
        ),
        ("<%= 7*7 %>", "ERB (Ruby)", lambda r: "49" in r),
    ]

    def __init__(self, config, target):
        self.config = config
        self.target = target
        self.logger = logging.getLogger(__name__)

    async def run(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        params: list[tuple[str, str]],
    ) -> list[dict]:
        """对每个参数注入 SSTI payload，检测响应

        Args:
            client: httpx 异步客户端
            base_url: 目标基础 URL
            params: [(param_name, param_value), ...] 待测试参数列表

        Returns:
            漏洞发现列表，每项含 vuln_type, url, param, payload, severity, evidence, description
        """
        findings = []
        seen: set[tuple[str, str, str]] = set()

        for param_name, param_value in params:
            for payload, engine_name, check_fn in self.PAYLOADS:
                # 构造注入 URL
                test_url = self._inject_param(base_url, param_name, param_value, payload)
                try:
                    resp = await client.get(
                        test_url,
                        follow_redirects=False,
                        timeout=10,
                    )
                    body = resp.text
                except Exception:
                    continue

                # 检查响应
                if check_fn(body):
                    key = (param_name, payload, engine_name)
                    if key in seen:
                        continue
                    seen.add(key)

                    # 确认性 payload — 如果能拿到 config/context，说明是真正的 Jinja2
                    if engine_name in ("Jinja2/Twig", "Freemarker"):
                        confirm_payload = "{{config}}" if engine_name == "Jinja2/Twig" else "${7*7}"
                        is_confirmed = False
                        try:
                            confirm_url = self._inject_param(
                                base_url, param_name, param_value, confirm_payload
                            )
                            confirm_resp = await client.get(
                                confirm_url, follow_redirects=False, timeout=10
                            )
                            confirm_body = confirm_resp.text
                            if engine_name == "Jinja2/Twig":
                                if "SECRET" in confirm_body or "DEBUG" in confirm_body:
                                    is_confirmed = True
                            else:
                                if "49" in confirm_body:
                                    is_confirmed = True
                        except Exception:
                            pass

                        if not is_confirmed and engine_name != "Jinja2/Twig":
                            # 以 `${7*7}` 为基准的引擎，无确认信息也保留
                            pass

                    findings.append({
                        "vuln_type": "ssti",
                        "url": test_url,
                        "param": param_name,
                        "payload": payload,
                        "severity": "high",
                        "engine": engine_name,
                        "evidence": f"响应包含预期的 SSTI 反馈 (引擎: {engine_name})",
                        "description": (
                            f"SSTI 模板注入漏洞 ({engine_name}) — "
                            f"参数 {param_name} 存在 {engine_name} 模板注入，"
                            f"可执行任意服务器端模板代码"
                        ),
                    })
                    self.logger.info(
                        "  [SSTI] 发现 %s 注入: %s?%s=%s",
                        engine_name, base_url, param_name, payload,
                    )

        return findings

    def _inject_param(
        self,
        base_url: str,
        param_name: str,
        original: str,
        payload: str,
    ) -> str:
        """在指定 URL 参数中注入 payload"""
        from urllib.parse import urlparse, parse_qs, urlencode

        parsed = urlparse(base_url)
        query_params = parse_qs(parsed.query)

        if query_params:
            query_params[param_name] = [payload]
            new_query = urlencode(query_params, doseq=True)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        else:
            sep = "&" if "?" in base_url else "?"
            return f"{base_url}{sep}{param_name}={payload}"
