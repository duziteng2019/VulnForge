"""信息收集模块 — 子域名、端口、指纹、爬虫"""

import asyncio
import json
import re
import socket
import ssl
from pathlib import Path
from typing import Optional

import httpx
from bs4 import BeautifulSoup

from ..core.config import VulnForgeConfig
from ..core.target import Target


class ReconRunner:
    """信息收集执行器"""

    def __init__(self, config: VulnForgeConfig, target: Target):
        self.config = config
        self.target = target
        self.results = {
            "domain": target.domain,
            "url": target.url,
            "ip": None,
            "ports": [],
            "subdomains": [],
            "technologies": [],
            "endpoints": [],
            "forms": [],
            "emails": [],
            "status": {},
        }

    async def run(self, output_dir: Path) -> dict:
        """执行全量信息收集"""
        tasks = []

        if self.config.get("recon.enable_subdomain", True):
            tasks.append(self._gather_subdomains())
        if self.config.get("recon.enable_portscan", True):
            tasks.append(self._port_scan())
        if self.config.get("recon.enable_fingerprint", True):
            tasks.append(self._fingerprint())
        if self.config.get("recon.enable_crawler", True):
            tasks.append(self._crawl())

        # 基本DNS解析先做
        await self._resolve_dns()

        if tasks:
            await asyncio.gather(*tasks)

        # 保存结果
        with open(output_dir / "recon.json", "w", encoding="utf-8") as f:
            json.dump(self.results, f, ensure_ascii=False, indent=2, default=str)

        # 打印摘要
        print(f"  [✓] DNS: {self.results['ip']}")
        print(f"  [✓] 端口: {len(self.results['ports'])} 个")
        print(f"  [✓] 子域名: {len(self.results['subdomains'])} 个")
        print(f"  [✓] 技术栈: {len(self.results['technologies'])} 项")
        print(f"  [✓] 端点: {len(self.results['endpoints'])} 个")
        print(f"  [✓] 表单: {len(self.results['forms'])} 个")

        return self.results

    async def _resolve_dns(self) -> None:
        """DNS解析"""
        try:
            info = await asyncio.get_event_loop().getaddrinfo(
                self.target.domain, 80
            )
            if info:
                self.results["ip"] = info[0][4][0]
        except Exception as e:
            print(f"  [!] DNS解析失败: {e}")

    async def _gather_subdomains(self) -> None:
        """子域名收集"""
        subdomains = set()

        # 常见子域名爆破
        common_subs = [
            "www", "mail", "api", "admin", "blog", "dev", "test",
            "stage", "beta", "app", "m", "mobile", "cdn", "static",
            "img", "css", "js", "assets", "upload", "download",
            "sso", "oauth", "login", "auth", "gitlab", "jenkins",
            "grafana", "kibana", "prometheus", "wiki", "confluence",
            "jira", "nexus", "sonar", "backup", "db",
            "database", "mysql", "redis", "elastic", "es", "mq",
            "rabbitmq", "kafka", "consul", "vault",
        ]

        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            tasks = []
            for sub in common_subs:
                domain = f"{sub}.{self.target.domain}"
                tasks.append(self._check_subdomain(client, domain))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if r and isinstance(r, str):
                    subdomains.add(r)

        self.results["subdomains"] = sorted(subdomains)

    async def _check_subdomain(self, client: httpx.AsyncClient, domain: str) -> Optional[str]:
        """检查子域名是否存活"""
        for proto in ("https", "http"):
            try:
                resp = await client.get(
                    f"{proto}://{domain}",
                    follow_redirects=True,
                    timeout=5,
                )
                if resp.status_code < 500:
                    return domain
            except Exception:
                continue
        return None

    async def _port_scan(self) -> None:
        """端口扫描（异步TCP连接检测）"""
        top_ports = [
            21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143,
            389, 443, 445, 464, 465, 587, 593, 636, 993, 995, 1433,
            1521, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181,
            2375, 2376, 2379, 2380, 3000, 3306, 3389, 3690, 4000,
            4040, 4243, 4444, 5000, 5001, 5002, 5432, 5555, 5601,
        ]

        async def check_port(port: int) -> Optional[dict]:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target.domain, port),
                    timeout=2.0,
                )
                writer.close()
                await writer.wait_closed()
                try:
                    service = socket.getservbyport(port) or "unknown"
                except Exception:
                    service = "unknown"
                is_ssl = port in (443, 8443, 9443) or self._check_ssl_service(port)
                return {"port": port, "service": service, "ssl": is_ssl}
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None

        tasks = [check_port(p) for p in top_ports]
        results = await asyncio.gather(*tasks)
        self.results["ports"] = [r for r in results if r is not None]

    def _check_ssl_service(self, port: int) -> bool:
        """检测端口是否运行SSL服务"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection(
                (self.target.domain, port), timeout=2
            ) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.target.domain):
                    return True
        except Exception:
            return False

    async def _fingerprint(self) -> None:
        """Web指纹识别"""
        tech_signatures = {
            "nginx": ["nginx", "x-powered-by: nginx"],
            "apache": ["apache", "x-powered-by: apache"],
            "iis": ["iis", "x-powered-by: asp.net"],
            "cloudflare": ["cloudflare", "cf-ray"],
            "wordpress": ["wp-content", "wp-admin", "wordpress"],
            "drupal": ["drupal", "sites/default"],
            "joomla": ["joomla", "com_content"],
            "php": [".php", "x-powered-by: php"],
            "python/django": ["django", "csrftoken", "sessionid"],
            "python/flask": ["flask", "werkzeug"],
            "java/spring": ["spring", "java", "jsessionid"],
            "node/express": ["express", "connect.sid"],
            "ruby/rails": ["rails", "ruby on rails"],
            "go": ["golang"],
            "vue.js": ["vue", "__nuxt"],
            "react": ["react", "create-react-app"],
            "angular": ["angular", "ng-"],
            "jquery": ["jquery", "jquery.js"],
            "bootstrap": ["bootstrap", "bootstrap.min.css"],
            "weblogic": ["weblogic", "bea"],
            "tomcat": ["tomcat", "apache-tomcat"],
            "jboss": ["jboss"],
            "jenkins": ["jenkins", "x-jenkins"],
            "gitlab": ["gitlab", "_gitlab"],
            "grafana": ["grafana"],
            "prometheus": ["prometheus", "/metrics"],
            "swagger": ["swagger", "api-docs", "openapi"],
            "shiro": ["shiro", "rememberMe"],
        }

        techs = []

        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            try:
                resp = await client.get(
                    self.target.base_url,
                    follow_redirects=True,
                    timeout=15,
                )
                headers_text = str(resp.headers).lower()
                body_text = resp.text[:50000].lower()

                # 服务端技术检测
                server = resp.headers.get("server", "").lower()
                if server:
                    techs.append(server)

                # 签名匹配
                for tech, sigs in tech_signatures.items():
                    for sig in sigs:
                        if sig.lower() in headers_text or sig.lower() in body_text:
                            techs.append(tech)
                            break

            except Exception:
                pass

        self.results["technologies"] = sorted(set(techs))

    async def _crawl(self) -> None:
        """基础爬虫 — 发现端点、表单、邮箱"""
        endpoints = set()
        forms = []
        emails = set()

        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            try:
                resp = await client.get(
                    self.target.base_url,
                    follow_redirects=True,
                    timeout=15,
                )
                soup = BeautifulSoup(resp.text, "lxml")

                # 提取所有链接
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if href.startswith("http"):
                        endpoints.add(href)
                    elif href.startswith("/") or href.startswith("?"):
                        full_url = self.target.resolve_path(href)
                        endpoints.add(full_url)

                # 提取表单
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    method = form.get("method", "get").upper()
                    inputs = []
                    for inp in form.find_all(["input", "textarea", "select"]):
                        inp_name = inp.get("name", "")
                        inp_type = inp.get("type", "text")
                        if inp_name:
                            inputs.append({"name": inp_name, "type": inp_type})
                    forms.append({
                        "action": action,
                        "method": method,
                        "inputs": inputs,
                        "url": self.target.resolve_path(action) if action else self.target.base_url,
                    })

                # 提取邮箱
                email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
                found_emails = re.findall(email_pattern, resp.text)
                emails.update(found_emails)

            except Exception:
                pass

        self.results["endpoints"] = sorted(endpoints)
        self.results["forms"] = forms
        self.results["emails"] = list(emails)
