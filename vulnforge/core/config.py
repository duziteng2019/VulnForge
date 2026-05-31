"""VulnForge 配置管理"""

import json
import os
from pathlib import Path
from typing import Optional


DEFAULT_CONFIG_DIR = Path.home() / ".vulnforge"
DEFAULT_CONFIG_PATH = DEFAULT_CONFIG_DIR / "config.json"

DEFAULT_CONFIG = {
    "ai_provider": "deepseek",
    "api_key": "",
    "api_base": "",
    "model": "deepseek-chat",
    "output_dir": str(DEFAULT_CONFIG_DIR / "scans"),
    "timeout": 30,
    "max_concurrent": 5,
    "proxy": "",
    "recon": {
        "enable_subdomain": True,
        "enable_portscan": True,
        "enable_fingerprint": True,
        "enable_crawler": True,
        "subdomain_depth": 2,
        "port_range": "1-10000",
    },
    "scanner": {
        "enable_sqli": True,
        "enable_xss": True,
        "enable_ssrf": True,
        "enable_cmd_inject": True,
        "enable_dir_scan": True,
        "payload_depth": "normal",  # light / normal / deep
    },
    "ai": {
        "enable_analysis": True,
        "enable_poc_generation": True,
        "enable_report": True,
        "temperature": 0.3,
        "max_tokens": 4096,
    },
}


class VulnForgeConfig:
    """配置管理器"""

    def __init__(self, data: dict):
        self.data = data

    @classmethod
    def load(cls, path: Optional[str] = None) -> "VulnForgeConfig":
        path = path or str(DEFAULT_CONFIG_PATH)
        config_path = Path(path)

        if config_path.exists():
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                # 合并默认值，确保新字段存在
                merged = DEFAULT_CONFIG.copy()
                merged.update(data)
                return cls(merged)

        return cls(DEFAULT_CONFIG.copy())

    def save(self, path: Optional[str] = None) -> None:
        path = path or str(DEFAULT_CONFIG_PATH)
        config_path = Path(path)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)

    def get(self, key: str, default=None):
        keys = key.split(".")
        value = self.data
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
        return value if value is not None else default

    def set(self, key: str, value) -> None:
        keys = key.split(".")
        target = self.data
        for k in keys[:-1]:
            if k not in target:
                target[k] = {}
            target = target[k]
        target[keys[-1]] = value
        self.save()

    @property
    def output_dir(self) -> str:
        return self.get("output_dir", str(DEFAULT_CONFIG_DIR / "scans"))
