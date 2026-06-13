"""CORS 配置检查模块"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class CORSChecker:
    """CORS 配置安全检查器"""

    def __init__(self, config, target):
        self.config = config
        self.target = target
        self.findings: list[dict] = []

    async def run(self, client, base_url: str) -> list[dict]:
        """执行全部 CORS 测试

        Args:
            client: httpx.AsyncClient
            base_url: 目标基础 URL

        Returns:
            发现列表 list[dict]
        """
        self.findings = []

        await self._test_origin_reflection(client, base_url)
        await self._test_wildcard(client, base_url)
        await self._test_preflight(client, base_url)

        return self.findings

    async def _test_origin_reflection(self, client, url: str) -> None:
        """测试 Origin 反射

        发送带恶意 Origin 的请求，检查响应是否反射该值
        """
        evil_origin = "https://evil.com"
        test_url = url.rstrip("/") + "/"
        try:
            resp = await client.get(
                test_url,
                headers={
                    "Origin": evil_origin,
                    "Referer": "https://evil.com/",
                },
                follow_redirects=False,
                timeout=10,
            )

            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")

            if acao == evil_origin:
                severity = "high"
                description = (
                    "CORS Origin 反射 — 服务端动态反射请求的 Origin 头，"
                    "攻击者可在恶意站点上构造跨域请求读取敏感数据"
                )
                evidence = (
                    f"Origin: {evil_origin} → "
                    f"Access-Control-Allow-Origin: {acao}"
                )

                # 如果同时允许凭据，则漏洞更严重
                if acac.lower() == "true":
                    severity = "critical"
                    description += "（且允许携带凭据）"
                    evidence += " | Access-Control-Allow-Credentials: true"

                self.findings.append({
                    "vuln_type": "cors_origin_reflection",
                    "url": test_url,
                    "severity": severity,
                    "evidence": evidence,
                    "description": description,
                })
                logger.info(f"  [CORS] 发现 Origin 反射: {test_url}")
        except Exception as e:
            logger.debug("  [!] CORS Origin 反射测试异常: %s", e)

    async def _test_wildcard(self, client, url: str) -> None:
        """测试通配符 CORS 配置和凭证+通配符错误配置"""
        test_url = url.rstrip("/") + "/"
        try:
            resp = await client.get(
                test_url,
                follow_redirects=False,
                timeout=10,
            )

            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")

            if acao == "*":
                severity = "medium"
                description = (
                    "CORS 通配符配置 — Access-Control-Allow-Origin: * "
                    "允许任意源访问资源"
                )
                evidence = "Access-Control-Allow-Origin: *"

                # 凭证+通配符：严重错误
                if acac.lower() == "true":
                    severity = "critical"
                    description = (
                        "CORS 严重配置错误 — 同时存在 "
                        "Access-Control-Allow-Origin: * 和 "
                        "Access-Control-Allow-Credentials: true，"
                        "攻击者可构造恶意页面窃取用户凭据"
                    )
                    evidence = (
                        "Access-Control-Allow-Origin: * | "
                        "Access-Control-Allow-Credentials: true"
                    )

                self.findings.append({
                    "vuln_type": "cors_wildcard",
                    "url": test_url,
                    "severity": severity,
                    "evidence": evidence,
                    "description": description,
                })
                logger.info(f"  [CORS] 发现通配符配置: {test_url} → {evidence}")
        except Exception as e:
            logger.debug("  [!] CORS 通配符测试异常: %s", e)

    async def _test_preflight(self, client, url: str) -> None:
        """测试预检请求

        检查 OPTIONS 响应是否允许不安全的方法和头
        """
        test_url = url.rstrip("/") + "/"

        # 测试各种 Origin 的预检请求
        test_origins = ["https://evil.com", None]
        headers_bases = [
            {"Origin": "https://evil.com", "Access-Control-Request-Method": "PUT"},
            {
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "x-custom-header",
            },
            {
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "DELETE",
                "Access-Control-Request-Headers": "authorization, x-requested-with",
            },
            # 无 Origin 的预检请求
            {
                "Access-Control-Request-Method": "PUT",
            },
        ]

        for req_headers in headers_bases:
            try:
                resp = await client.options(
                    test_url,
                    headers=req_headers,
                    follow_redirects=False,
                    timeout=10,
                )

                if resp.status_code not in (200, 204):
                    continue

                acao = resp.headers.get("access-control-allow-origin", "")
                acam = resp.headers.get("access-control-allow-methods", "")
                acah = resp.headers.get("access-control-allow-headers", "")
                acac = resp.headers.get("access-control-allow-credentials", "")
                max_age = resp.headers.get("access-control-max-age", "")

                # 检查是否允许不安全的方法
                allowed_methods = [m.strip().upper() for m in acam.split(",") if m.strip()] if acam else []
                unsafe_methods = [m for m in allowed_methods if m in ("PUT", "DELETE", "PATCH", "TRACE", "CONNECT")]

                # 检查是否允许不安全的头
                allowed_headers = [h.strip().lower() for h in acah.split(",") if h.strip()] if acah else []
                unsafe_headers = [h for h in allowed_headers if h in ("authorization", "x-custom-header")]

                # 构建描述和证据
                parts = []
                if acao:
                    parts.append(f"Access-Control-Allow-Origin: {acao}")
                if acam:
                    parts.append(f"Access-Control-Allow-Methods: {acam}")
                if acah:
                    parts.append(f"Access-Control-Allow-Headers: {acah}")
                if acac:
                    parts.append(f"Access-Control-Allow-Credentials: {acac}")
                if max_age:
                    parts.append(f"Access-Control-Max-Age: {max_age}")

                if unsafe_methods or unsafe_headers:
                    severity = "medium"
                    desc_parts = []
                    if unsafe_methods:
                        desc_parts.append(f"不安全方法: {', '.join(unsafe_methods)}")
                    if unsafe_headers:
                        desc_parts.append(f"不安全头: {', '.join(unsafe_headers)}")

                    self.findings.append({
                        "vuln_type": "cors_preflight_permissive",
                        "url": test_url,
                        "severity": severity,
                        "evidence": " | ".join(parts),
                        "description": (
                            f"CORS 预检请求过于宽松 — {'; '.join(desc_parts)}。"
                            "攻击者可使用这些方法和头进行跨域攻击"
                        ),
                    })
                    logger.info(f"  [CORS] 预检请求过于宽松: {test_url}")
                    break  # 同一 URL 只需要报告一次

            except Exception as e:
                logger.debug("  [!] CORS 预检测试异常: %s", e)
                continue
