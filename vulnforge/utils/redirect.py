"""Open Redirect (开放重定向) 检测器

检测逻辑:
1. 发送带外部域名的参数到常见参数名
2. 检查响应 Location header 是否指向外部域名
3. 检查 body 中是否有 window.location 跳转到外部域名
4. 检查 30x 状态码
"""

import logging
from urllib.parse import urlparse, urljoin

import httpx


# 用于检测的外部域名
EVIL_HOST = "evil.com"
EVIL_URL = f"https://{EVIL_HOST}"

# 常见易受 Open Redirect 影响的参数名
TEST_PARAMS = [
    "url", "redirect", "next", "return", "return_to", "return_url",
    "target", "to", "dest", "destination", "out", "redirect_uri",
    "redirect_url", "callback", "continue", "forward", "forward_url",
    "view", "dir", "file", "load", "page", "site", "path",
    "referer", "ref", "source", "link", "goto",
]

PAYLOADS = [
    f"//{EVIL_HOST}",
    f"https://{EVIL_HOST}",
    f"http://{EVIL_HOST}",
    f"//{EVIL_HOST}/@target.com",
    f"//{EVIL_HOST}%23target.com",
    f"/\\\\{EVIL_HOST}",
    f"@{EVIL_HOST}",
    f"https://{EVIL_HOST}:443",
    f"//{EVIL_HOST}:443",
]

# 正则：检测 body 中的 JS 跳转
import re
WINDOW_LOCATION_RE = re.compile(
    r'(?:window|document\.location|location\.href|top\.location)\s*[=:]\s*["\']' +
    re.escape(EVIL_HOST) + r'["\']',
    re.IGNORECASE,
)


class OpenRedirectTester:
    """Open Redirect 检测器"""

    def __init__(self, config, target):
        self.config = config
        self.target = target
        self.logger = logging.getLogger(__name__)

    async def run(
        self,
        client: httpx.AsyncClient,
        base_url: str,
    ) -> list[dict]:
        """对每个参数+payload 测试 Open Redirect

        Args:
            client: httpx 异步客户端
            base_url: 目标基础 URL

        Returns:
            漏洞发现列表
        """
        findings = []
        seen: set[tuple[str, str]] = set()

        # 从 base_url 中获取原始参数，以便替换
        from urllib.parse import parse_qs

        parsed = urlparse(base_url)
        existing_params = parse_qs(parsed.query)

        test_params = []

        # 如果已有参数，用它们；否则使用常见参数名
        if existing_params:
            for name in existing_params:
                test_params.append(name)
        else:
            test_params = TEST_PARAMS

        for param_name in test_params:
            for payload in PAYLOADS:
                test_url = self._build_url(base_url, param_name, payload)
                key = (param_name, payload)
                if key in seen:
                    continue

                try:
                    resp = await client.get(
                        test_url,
                        follow_redirects=False,
                        timeout=10,
                    )
                except Exception:
                    continue

                status = resp.status_code

                # --- 检查 1: 30x + Location header 指向 evil.com ---
                location = resp.headers.get("location", "")
                if location and EVIL_HOST in location.lower():
                    seen.add(key)
                    findings.append({
                        "vuln_type": "open_redirect",
                        "url": test_url,
                        "param": param_name,
                        "payload": payload,
                        "severity": "medium",
                        "evidence": (
                            f"HTTP {status} + Location: {location[:120]}"
                        ),
                        "description": (
                            f"Open Redirect 漏洞 — 参数 {param_name} "
                            f"导致服务器端重定向到外部域名 {EVIL_HOST}"
                        ),
                    })
                    self.logger.info(
                        "  [OpenRedirect] 发现服务器端重定向: %s?%s=%s",
                        base_url, param_name, payload,
                    )
                    continue

                # --- 检查 2: 响应 body 中的 window.location 跳转 ---
                body = resp.text
                if WINDOW_LOCATION_RE.search(body):
                    seen.add(key)
                    findings.append({
                        "vuln_type": "open_redirect",
                        "url": test_url,
                        "param": param_name,
                        "payload": payload,
                        "severity": "medium",
                        "evidence": "响应中包含 window.location 跳转到 evil.com",
                        "description": (
                            f"Open Redirect (客户端跳转) — 参数 {param_name} "
                            f"导致客户端 JS 跳转到外部域名 {EVIL_HOST}"
                        ),
                    })
                    self.logger.info(
                        "  [OpenRedirect] 发现客户端 JS 跳转: %s?%s=%s",
                        base_url, param_name, payload,
                    )
                    continue

                # --- 检查 3: Meta refresh 跳转 ---
                meta_refresh = re.search(
                    r'<meta\s+http-equiv=["\']refresh["\'][^>]*content=["\']\d*;?\s*url=([^"\']+)',
                    body,
                    re.IGNORECASE,
                )
                if meta_refresh:
                    meta_url = meta_refresh.group(1).strip()
                    if EVIL_HOST in meta_url.lower():
                        seen.add(key)
                        findings.append({
                            "vuln_type": "open_redirect",
                            "url": test_url,
                            "param": param_name,
                            "payload": payload,
                            "severity": "medium",
                            "evidence": f"Meta refresh 跳转到 {meta_url}",
                            "description": (
                                f"Open Redirect (Meta Refresh) — 参数 {param_name} "
                                f"导致 Meta Refresh 跳转到外部域名 {EVIL_HOST}"
                            ),
                        })
                        self.logger.info(
                            "  [OpenRedirect] 发现 Meta Refresh 跳转: %s?%s=%s",
                            base_url, param_name, payload,
                        )

        return findings

    def _build_url(self, base_url: str, param_name: str, payload: str) -> str:
        """构造带注入参数的 URL"""
        from urllib.parse import urlparse, urlencode, parse_qs

        parsed = urlparse(base_url)
        query_params = parse_qs(parsed.query)

        if query_params:
            query_params[param_name] = [payload]
            new_query = urlencode(query_params, doseq=True)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        else:
            sep = "&" if "?" in base_url else "?"
            return f"{base_url}{sep}{param_name}={payload}"
