"""VulnForge 目标管理 — 扫描目标对象"""

from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse, urljoin
import re


@dataclass
class Target:
    """扫描目标对象"""

    url: str
    domain: str = ""
    scheme: str = "https"
    base_path: str = ""
    ip: Optional[str] = None
    ports: List[int] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)

    def __post_init__(self):
        parsed = urlparse(self.url if "://" in self.url else f"https://{self.url}")
        self.scheme = parsed.scheme or "https"
        self.domain = parsed.netloc or parsed.hostname or ""
        self.base_path = parsed.path.rstrip("/") if parsed.path else ""

        # Clean domain (remove port)
        if ":" in self.domain:
            self.domain = self.domain.split(":")[0]

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.domain}"

    @property
    def is_ip(self) -> bool:
        return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", self.domain))

    def resolve_path(self, path: str) -> str:
        """拼接完整URL"""
        return urljoin(self.base_url, path)
