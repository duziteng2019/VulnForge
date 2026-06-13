"""信息收集模块 — 子域名、端口、指纹、爬虫（增强版）"""

import asyncio
import json
import logging
import re
import socket
import ssl
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from ..core.config import VulnForgeConfig
from ..core.target import Target


class ReconRunner:
    """信息收集执行器（增强版：200+子域名、top200端口、50+指纹、递归爬虫2层）"""

    def __init__(self, config: VulnForgeConfig, target: Target):
        self.config = config
        self.target = target
        self.logger = logging.getLogger(__name__)
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
        output_dir.mkdir(parents=True, exist_ok=True)
        with open(output_dir / "recon.json", "w", encoding="utf-8") as f:
            json.dump(self.results, f, ensure_ascii=False, indent=2, default=str)

        # 打印摘要
        self.logger.info("信息收集完成:")
        self.logger.info("  DNS: %s", self.results["ip"])
        self.logger.info("  端口: %d 个", len(self.results["ports"]))
        self.logger.info("  子域名: %d 个", len(self.results["subdomains"]))
        self.logger.info("  技术栈: %d 项", len(self.results["technologies"]))
        self.logger.info("  端点: %d 个", len(self.results["endpoints"]))
        self.logger.info("  表单: %d 个", len(self.results["forms"]))

        return self.results

    # ── DNS ──────────────────────────────────────────────────────────

    async def _resolve_dns(self) -> None:
        """DNS解析"""
        try:
            info = await asyncio.get_event_loop().getaddrinfo(
                self.target.domain, 80
            )
            if info:
                self.results["ip"] = info[0][4][0]
                self.logger.debug("DNS解析成功: %s -> %s", self.target.domain, self.results["ip"])
        except Exception as e:
            self.logger.warning("DNS解析失败: %s", e)

    # ── 子域名 200+ ──────────────────────────────────────────────────

    SUBDOMAIN_LIST = [
        # 标准 & 通用
        "www", "mail", "api", "admin", "blog", "dev", "test",
        "stage", "beta", "app", "m", "mobile", "cdn", "static",
        "img", "css", "js", "assets", "upload", "download",
        "sso", "oauth", "auth", "login", "register", "signup",
        # DevOps & CI/CD
        "gitlab", "jenkins", "jira", "confluence", "nexus", "sonar",
        "grafana", "kibana", "prometheus", "nagios", "zabbix",
        "ansible", "puppet", "chef", "salt", "terraform",
        # 数据库 & 中间件
        "db", "database", "mysql", "postgres", "postgresql",
        "redis", "elastic", "es", "mq", "rabbitmq", "kafka",
        "consul", "vault", "phpmyadmin", "pma",
        # 容器 & 集群
        "docker", "k8s", "kubernetes", "registry",
        "harbor", "swarm", "nomad",
        # API 版本
        "v1", "v2", "v3", "v4",
        "api-v1", "api-v2", "api-v3",
        "rest", "graphql", "grpc",
        # Web 服务 & 反向代理
        "nginx", "apache", "tomcat", "iis",
        "traefik", "caddy", "haproxy", "envoy",
        "istio", "kong", "apisix",
        # 监控 & 日志
        "monitor", "monitoring", "logs", "log",
        "metrics", "health", "healthcheck",
        "status", "statuspage", "uptime",
        "alerts", "alertmanager",
        # 开发 & 测试
        "staging", "stg", "preprod", "pre-prod",
        "devops", "ops", "tools", "util",
        "sandbox", "playground", "demo", "sample", "example",
        "canary", "alpha", "preview", "release",
        # 文档 & 帮助
        "docs", "doc", "wiki", "help", "support",
        "faq", "manual", "guide", "tutorial",
        "forum", "community",
        # 业务功能
        "shop", "store", "cart", "checkout",
        "payment", "pay", "invoice", "billing",
        "account", "profile", "user", "users",
        "dashboard", "panel", "cp", "manager",
        "config", "settings", "setup", "install",
        # 安全 & 认证
        "idp", "saml", "ldap", "radius",
        "otp", "2fa", "mfa",
        "captcha", "recaptcha",
        # 邮箱 & 通讯
        "webmail", "email", "imap", "pop3", "smtp",
        "mailgun", "sendgrid", "postfix", "dovecot",
        "exim", "qmail",
        # 文件 & 媒体
        "files", "file", "media", "video", "audio",
        "image", "images", "photo", "photos", "picture", "pictures",
        "gallery", "portfolio",
        # SEO & 标准
        "favicon", "robots", "sitemap",
        "crossdomain", "crossdomain.xml",
        "humans", "security", "security.txt",
        # CMS & 框架
        "wp", "wp-content", "wp-admin", "wp-includes",
        "wordpress", "drupal", "joomla", "magento",
        "shopify", "squarespace", "wix",
        # 移动 & 小程序
        "ios", "android", "h5", "mini", "mini-program",
        "wechat", "alipay", "baidu", "toutiao", "douyin",
        # 第三方集成
        "slack", "teams", "discord", "telegram",
        "zoom", "meet", "teams",
        "salesforce", "zendesk", "freshdesk",
        "sentry", "datadog", "newrelic",
        # 内部系统
        "intranet", "internal", "corp", "corporate",
        "hr", "payroll", "timesheet",
        "ldap", "ad", "active-directory",
        "vpn", "openvpn", "wireguard",
        "proxy", "squid", "forward",
        # 备份 & 迁移
        "backup", "backups", "migration", "migrate",
        "upgrade", "update", "patch",
        "recovery", "disaster",
        # 其它常见
        "server-status", "server-info",
        "debug", "trace", "profile", "profiler",
        "webhook", "callback", "hook",
        "redirect", "short", "shortener",
        "stream", "events", "event",
        "live", "tv", "radio",
        "news", "press", "publications",
        "careers", "jobs", "recruit",
        "about", "contact", "terms", "privacy",
        "partners", "affiliates", "reseller",
        "license", "licensing", "billing",
        # 含连字符
        "www-dev", "www-staging", "www-test",
        "my-account", "my-account",
        "self-service", "customer-portal",
        "partner-portal", "vendor-portal",
        "cdn-1", "cdn-2", "cdn-3",
        "static-1", "static-2",
        "origin-1", "origin-2",
        "edge-1", "edge-2",
    ]

    async def _gather_subdomains(self) -> None:
        """子域名收集（200+ 常见子域名爆破）"""
        discovered = set()
        semaphore = asyncio.Semaphore(30)  # 并发控制

        async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
            tasks = []
            for sub in self.SUBDOMAIN_LIST:
                domain = f"{sub}.{self.target.domain}"
                tasks.append(self._check_subdomain(client, domain, semaphore))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if r and isinstance(r, str):
                    discovered.add(r)

        self.results["subdomains"] = sorted(discovered)
        self.logger.info("发现 %d 个子域名", len(discovered))

    async def _check_subdomain(
        self, client: httpx.AsyncClient, domain: str, semaphore: asyncio.Semaphore
    ) -> Optional[str]:
        """检查子域名是否存活"""
        async with semaphore:
            for proto in ("https", "http"):
                try:
                    resp = await client.get(
                        f"{proto}://{domain}",
                        timeout=5,
                    )
                    if resp.status_code < 500:
                        self.logger.debug("子域名存活: %s (%d)", domain, resp.status_code)
                        return domain
                except Exception:
                    continue
        return None

    # ── 端口扫描 top 200 ─────────────────────────────────────────────

    TOP_PORTS = [
        # 1-100 (well-known)
        21, 22, 23, 25, 53, 80, 81, 88, 110, 111,
        135, 139, 143, 389, 443, 445, 464, 465, 587, 593,
        636, 993, 995,
        # 100-1000
        1433, 1521, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
        2181, 2375, 2376, 2379, 2380, 3000, 3306, 3389, 3690,
        4000, 4040, 4243, 4444, 5000, 5001, 5002, 5432, 5555,
        5601, 5672, 5900, 5901, 5984, 6000, 6001, 6379, 6443,
        7001, 7002, 7077,
        # 8000-8999
        8000, 8001, 8008, 8009, 8010, 8020, 8042, 8069,
        8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
        8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099,
        8100, 8181, 8200, 8222, 8300, 8400, 8443, 8500,
        8530, 8531, 8585, 8600, 8649, 8686, 8787, 8800, 8834,
        8880, 8888, 8889,
        # 8900-9999
        8983, 9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, 9010,
        9042, 9050, 9060, 9080, 9090, 9091, 9092, 9093, 9094, 9095, 9096, 9097, 9098, 9099,
        9100, 9200, 9300, 9418, 9443, 9500, 9600, 9700, 9797, 9800,
        9869, 9900, 9999,
        # 10000-19999
        10000, 10050, 10051, 10080,
        11211, 11214, 11215,
        12345,
        15672, 16010, 16379, 16380,
        17000, 18080, 18081,
        19000, 19150, 19200,
        # 20000-29999
        20000, 21000, 22000, 22222,
        23456, 24444,
        25565, 25672,
        26000, 27000, 27017, 27018, 27019,
        28000, 28017,
        # 30000-39999
        30000, 31234, 32400,
        32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775,
        32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784,
        32785, 32786, 32787, 32788, 32789, 32790,
        33333, 34443, 37777,
        # 40000-49999
        40000, 41000, 42000, 43000, 44000,
        44444, 45000, 46000, 47000, 48000, 49000,
        49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160,
        49161, 49162, 49163, 49164, 49165, 49166, 49167, 49168, 49169,
        49170, 49171, 49172, 49173, 49174, 49175, 49176, 49177, 49178, 49179,
        49180, 49181, 49182, 49183, 49184, 49185, 49186, 49187, 49188, 49189,
        49190, 49191, 49192, 49193, 49194, 49195, 49196, 49197, 49198, 49199,
        # 50000-59999
        50000, 50001, 50002, 50003, 50004, 50005, 50006, 50007, 50008, 50009,
        50010, 50020, 50030, 50050, 50060, 50070, 50075, 50090, 50095, 50100,
        50200, 50300, 50400, 50500, 50600, 50700, 50800, 50900,
        51000, 51100, 51200, 51300, 51400, 51500, 51600, 51700, 51800, 51900,
        52000, 52100, 52200, 52300, 52400, 52500, 52600, 52700, 52800, 52900,
        53000, 53100, 53200, 53300, 53400, 53500, 53600, 53700, 53800, 53900,
        54000, 54100, 54200, 54300, 54400, 54500, 54600, 54700, 54800, 54900,
        55000, 55100, 55200, 55300, 55400, 55500, 55600, 55700, 55800, 55900,
        56000, 56100, 56200, 56300, 56400, 56500, 56600, 56700, 56800, 56900,
        57000, 57100, 57200, 57300, 57400, 57500, 57600, 57700, 57800, 57900,
        58000, 58100, 58200, 58300, 58400, 58500, 58600, 58700, 58800, 58900,
        59000, 59100, 59200, 59300, 59400, 59500, 59600, 59700, 59800, 59900,
        # 60000-65535
        60000, 60020, 60030, 60040, 60050, 60060, 60070, 60080, 60090, 60100,
        60200, 60300, 60400, 60500, 60600, 60700, 60800, 60900,
        61000, 62000, 63000, 64000, 65000,
        65301, 65389, 65400, 65535,
    ]

    async def _port_scan(self) -> None:
        """端口扫描（异步TCP连接检测 — top 200 端口）"""
        semaphore = asyncio.Semaphore(100)  # 并发限制

        async def check_port(port: int) -> Optional[dict]:
            async with semaphore:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.target.domain, port),
                        timeout=2.0,
                    )
                    writer.close()
                    await writer.wait_closed()
                    try:
                        service = socket.getservbyport(port, "tcp") or "unknown"
                    except (OSError, ValueError):
                        service = "unknown"
                    is_ssl = port in (443, 8443, 9443) or self._check_ssl_service(port)
                    self.logger.debug("端口开放: %d (%s)", port, service)
                    return {"port": port, "service": service, "ssl": is_ssl}
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return None

        tasks = [check_port(p) for p in self.TOP_PORTS]
        results = await asyncio.gather(*tasks)
        self.results["ports"] = sorted(
            [r for r in results if r is not None], key=lambda x: x["port"]
        )
        self.logger.info("发现 %d 个开放端口", len(self.results["ports"]))

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

    # ── 指纹识别 50+ ─────────────────────────────────────────────────

    TECH_SIGNATURES = {
        # 静态 / SPA 框架
        "next.js": ["next.js", "_next/static", "__next"],
        "nuxt": ["nuxt", "_nuxt/static", "__nuxt"],
        "gatsby": ["gatsby", "___gatsby"],
        "hugo": ["hugo", "HUGO_VERSION"],
        "hexo": ["hexo", "hexo-generator"],
        "jekyll": ["jekyll", "github.com/jekyll"],
        "eleventy": ["eleventy", "11ty"],
        "docusaurus": ["docusaurus", "__docusaurus"],
        "astro": ["astro", "_astro"],
        "sveltekit": ["sveltekit", "svelte"],
        "solidstart": ["solidstart", "solid-js"],
        "remix": ["remix", "_remix"],
        # JavaScript 运行时 / 后端
        "bun": ["bun/", "server: bun"],
        "deno": ["deno/", "server: deno"],
        "fastify": ["fastify", "x-powered-by: fastify"],
        "hono": ["hono", "x-powered-by: hono"],
        # Web 服务器
        "nginx": ["nginx", "x-powered-by: nginx", "server: nginx"],
        "nginx-unit": ["nginx-unit", "server: unit"],
        "caddy": ["caddy", "server: caddy"],
        "caddy2": ["caddy2"],
        "traefik": ["traefik", "x-powered-by: traefik"],
        "apache": ["apache", "x-powered-by: apache", "server: apache"],
        "iis": ["iis", "x-powered-by: asp.net", "server: microsoft-iis"],
        "lighttpd": ["lighttpd", "server: lighttpd"],
        "cherokee": ["cherokee", "server: cherokee"],
        "squid": ["squid", "server: squid"],
        "varnish": ["varnish", "x-varnish"],
        "haproxy": ["haproxy", "x-powered-by: haproxy"],
        # 反向代理 / API 网关
        "kong": ["kong", "x-powered-by: kong"],
        "apisix": ["apisix", "x-powered-by: apisix"],
        "envoy": ["envoy", "server: envoy"],
        "istio": ["istio", "x-istio"],
        "openresty": ["openresty", "server: openresty"],
        "tengine": ["tengine", "server: tengine", "tengine"],
        # Java 应用服务器
        "tomcat": ["tomcat", "apache-tomcat", "x-powered-by: tomcat"],
        "resin": ["resin", "x-powered-by: resin"],
        "jetty": ["jetty", "server: jetty"],
        "wildfly": ["wildfly", "x-powered-by: wildfly"],
        "payara": ["payara", "x-powered-by: payara"],
        "glassfish": ["glassfish", "x-powered-by: glassfish"],
        "weblogic": ["weblogic", "bea", "x-powered-by: weblogic"],
        "websphere": ["websphere", "x-powered-by: websphere"],
        "jboss": ["jboss", "x-powered-by: jboss"],
        "undertow": ["undertow", "x-powered-by: undertow"],
        "netty": ["netty", "x-powered-by: netty"],
        # Python Web 框架
        "python/flask": ["flask", "werkzeug", "x-powered-by: flask"],
        "python/django": ["django", "csrftoken", "sessionid", "django-admin"],
        "python/fastapi": ["fastapi", "uvicorn", "starlette"],
        "python/aiohttp": ["aiohttp", "x-powered-by: aiohttp"],
        "python/tornado": ["tornado", "x-powered-by: tornado"],
        # Node.js 框架
        "node/express": ["express", "connect.sid", "x-powered-by: express"],
        "node/koa": ["koa", "x-powered-by: koa"],
        "node/nest": ["nest", "x-powered-by: nest"],
        # Ruby
        "ruby/rails": ["rails", "ruby on rails", "x-powered-by: rails"],
        "ruby/sinatra": ["sinatra", "x-powered-by: sinatra"],
        # Go
        "go": ["golang", "x-powered-by: golang"],
        "go/gin": ["gin", "x-powered-by: gin"],
        "go/echo": ["echo", "x-powered-by: echo"],
        "go/fiber": ["fiber", "x-powered-by: fiber"],
        # JVM 框架
        "java/spring": ["spring", "java", "jsessionid", "x-powered-by: spring"],
        "vert.x": ["vert.x", "vertx", "x-powered-by: vert.x"],
        "play": ["play framework", "x-powered-by: play"],
        "akka-http": ["akka", "akka-http"],
        "finagle": ["finagle", "twitter-server"],
        # CMS / 博客
        "wordpress": ["wp-content", "wp-admin", "wordpress", "wp-json"],
        "drupal": ["drupal", "sites/default", "drupal.js"],
        "joomla": ["joomla", "com_content", "joomla.js"],
        "magento": ["magento", "mage", "x-magento"],
        "shopify": ["shopify", "myshopify", "x-shopify"],
        # 前端框架
        "vue.js": ["vue", "__nuxt", "vue.js", "vuejs"],
        "react": ["react", "create-react-app", "react-dom", "react.js"],
        "angular": ["angular", "ng-", "angular.js"],
        "svelte": ["svelte", "svelte.js"],
        "jquery": ["jquery", "jquery.js"],
        "bootstrap": ["bootstrap", "bootstrap.min.css", "bootstrap.css"],
        # 开发 / CI 工具
        "jenkins": ["jenkins", "x-jenkins", "jenkins.io"],
        "gitlab": ["gitlab", "_gitlab", "gitlab-ci"],
        "grafana": ["grafana", "grafana.js", "x-grafana"],
        "prometheus": ["prometheus", "/metrics", "prometheus.js"],
        "sonarqube": ["sonarqube", "sonar", "x-sonar"],
        "nexus": ["nexus", "sonatype", "x-nexus"],
        # API 文档
        "swagger": ["swagger", "api-docs", "openapi", "swagger-ui"],
        "redoc": ["redoc", "redoc.js"],
        # 安全
        "shiro": ["shiro", "rememberMe"],
        "cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
        "akamai": ["akamai", "x-akamai"],
        "fastly": ["fastly", "x-fastly"],
        # 负载均衡 & 安全设备
        "nuster": ["nuster", "x-nuster"],
        "vcl": ["vcl", "x-vcl"],
        "pound": ["pound", "x-pounder"],
        "stud": ["stud", "x-stud"],
        "stunnel": ["stunnel", "x-stunnel"],
        # 其它
        "php": [".php", "x-powered-by: php", "php/"],
        "perl": ["perl", "x-powered-by: perl"],
    }

    async def _fingerprint(self) -> None:
        """Web指纹识别（50+ 技术栈）"""
        techs = []

        async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as client:
            try:
                resp = await client.get(
                    self.target.base_url,
                    timeout=15,
                )
                headers_text = str(resp.headers).lower()
                body_text = resp.text[:80000].lower()

                # 服务端 Server header
                server = resp.headers.get("server", "").lower()
                if server:
                    techs.append(server)

                # X-Powered-By header
                powered = resp.headers.get("x-powered-by", "").lower()
                if powered:
                    techs.append(powered)

                # 签名匹配
                for tech, sigs in self.TECH_SIGNATURES.items():
                    for sig in sigs:
                        sig_lower = sig.lower()
                        if sig_lower in headers_text or sig_lower in body_text:
                            techs.append(tech)
                            break

            except Exception as e:
                self.logger.warning("指纹识别请求失败: %s", e)

        # 尝试获取其它常见路径增强指纹
        extra_paths = ["/favicon.ico", "/robots.txt", "/sitemap.xml", "/.well-known/"]
        for path in extra_paths:
            try:
                resp = await client.get(
                    urljoin(self.target.base_url, path),
                    timeout=5,
                )
                body = resp.text[:10000].lower()
                for tech, sigs in self.TECH_SIGNATURES.items():
                    for sig in sigs:
                        if sig.lower() in body:
                            techs.append(tech)
                            break
            except Exception:
                continue

        self.results["technologies"] = sorted(set(techs))
        self.logger.info("识别到 %d 项技术栈", len(self.results["technologies"]))

    # ── 递归爬虫 2 层 ────────────────────────────────────────────────

    async def _crawl(self) -> None:
        """递归爬虫（深度2层）— 发现端点、表单、邮箱"""
        visited = set()
        endpoints = set()
        forms = []
        emails = set()

        domain = urlparse(self.target.base_url).netloc

        async with httpx.AsyncClient(
            timeout=15, verify=False, follow_redirects=True
        ) as client:

            async def fetch_and_parse(url: str, depth: int):
                """爬取并解析单个页面，深度≤2"""
                if depth > 2 or url in visited:
                    return
                visited.add(url)

                try:
                    self.logger.debug("爬取 [深度%d]: %s", depth, url)
                    resp = await client.get(url, timeout=15)
                except Exception as e:
                    self.logger.debug("爬取失败 %s: %s", url, e)
                    return

                soup = BeautifulSoup(resp.text, "lxml")

                # ── 提取链接 ──
                page_endpoints = set()
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"].strip()
                    full = urljoin(url, href)
                    parsed = urlparse(full)
                    # 只保留同域名、http(s) 的链接
                    if parsed.netloc == domain and parsed.scheme.startswith("http"):
                        # 去重 / 去锚点
                        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        if parsed.query:
                            clean_url += f"?{parsed.query}"
                        page_endpoints.add(clean_url)
                    elif parsed.netloc != domain and href.startswith("http"):
                        # 非同域链接也记录但不递归
                        endpoints.add(full)

                endpoints.update(page_endpoints)

                # ── 下层递归（深度+1） ──
                if depth < 2:
                    tasks = []
                    for child_url in list(page_endpoints)[:50]:  # 每层最多50个链接防止爆炸
                        if child_url not in visited:
                            tasks.append(fetch_and_parse(child_url, depth + 1))
                    if tasks:
                        await asyncio.gather(*tasks, return_exceptions=True)

                # ── 提取表单 ──
                for form_tag in soup.find_all("form"):
                    action = form_tag.get("action", "")
                    method = form_tag.get("method", "get").upper()
                    inputs = []
                    for inp in form_tag.find_all(["input", "textarea", "select"]):
                        inp_name = inp.get("name", "")
                        inp_type = inp.get("type", "text")
                        if inp_name:
                            inputs.append({"name": inp_name, "type": inp_type})
                    forms.append({
                        "action": action,
                        "method": method,
                        "inputs": inputs,
                        "url": urljoin(url, action) if action else url,
                    })

                # ── 提取邮箱 ──
                email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
                found_emails = re.findall(email_pattern, resp.text)
                emails.update(found_emails)

            # 从首页开始
            await fetch_and_parse(self.target.base_url, depth=1)

        self.results["endpoints"] = sorted(endpoints)
        self.results["forms"] = forms
        self.results["emails"] = list(emails)
        self.logger.info("爬虫结果: %d 端点, %d 表单, %d 邮箱",
                         len(endpoints), len(forms), len(emails))
