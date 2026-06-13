"""VulnForge 配置管理"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Optional

import httpx


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
        "enable_csrf": True,
        "enable_xxe": True,
        "enable_lfi": True,
        "enable_graphql": True,
        "enable_jwt": True,
        "enable_cors": True,
        "enable_ssti": True,
        "enable_redirect": True,
        "enable_race": True,
        "enable_fuzzing": False,  # 默认关闭，因为 fuzzing 会产生大量请求
        "enable_websocket": True,
        "payload_depth": "normal",
    },
    "auth": {
        "cookie": "",
        "auth_url": "",
        "auth_data": "",
        "auth_username": "",
        "auth_password": "",
    },
    "oob": {
        "enabled": True,
        "domain": "",
    },
    "browser": {
        "enabled": False,
        "headless": True,
        "screenshot": False,
    },
    "ai": {
        "enable_analysis": True,
        "enable_poc_generation": True,
        "enable_report": True,
        "temperature": 0.3,
        "max_tokens": 4096,
    },
    "fuzzing": {
        "max_params": 10,     # 最多 fuzz 的参数数
        "payload_types": "all",  # all / basic / deep
        "timeout_per_param": 30,  # 每个参数最大 fuzz 时间(秒)
    },
}

_API_KEY_PATTERN = re.compile(r"^sk-[A-Za-z0-9]{16,}$")


def validate_api_key(api_key: str) -> bool:
    """校验 API Key 不为空且格式有效。

    支持的格式:
      - DeepSeek / OpenAI 风格: 以 sk- 开头，后跟至少 16 个字母或数字
      - 纯字母数字（未分类/自托管）
    """
    if not api_key or not isinstance(api_key, str):
        return False
    api_key = api_key.strip()
    if not api_key:
        return False
    if api_key.startswith("sk-"):
        return bool(_API_KEY_PATTERN.match(api_key))
    return api_key.isalnum()


def create_shared_client(
    timeout: Optional[int] = None,
    config: Optional["VulnForgeConfig"] = None,
) -> httpx.AsyncClient:
    """创建一个共享的 httpx.AsyncClient 实例。

    参数:
        timeout: 请求超时秒数 (默认从 config 或 30)
        config: VulnForgeConfig 实例；未传入时自动加载默认配置

    返回:
        配置好的 httpx.AsyncClient（verify=False，支持代理）
    """
    if config is None:
        config = VulnForgeConfig.load()
    _timeout = timeout if timeout is not None else config.get("timeout", 30)
    proxy_url = config.get("proxy", "")

    client_kwargs = {
        "timeout": httpx.Timeout(_timeout),
        "verify": False,
        "follow_redirects": True,
    }
    if proxy_url:
        client_kwargs["proxy"] = proxy_url

    return httpx.AsyncClient(**client_kwargs)


async def create_authenticated_client(config: 'VulnForgeConfig', timeout: int = 30) -> httpx.AsyncClient:
    """创建已认证的共享 client

    1. 如果 config 有 cookie 字符串，解析并设置到 CookieJar
    2. 如果 config 有 auth_url + auth_data，POST 到 auth_url 获取 cookie
    3. 如果 config 有 auth_url + auth_username/auth_password，构造表单并 POST
    4. 均不满足则返回普通 client
    """
    client = httpx.AsyncClient(
        timeout=timeout,
        verify=False,
        follow_redirects=True,
    )

    cookie_str = config.get("auth.cookie", "")
    if cookie_str:
        from http.cookies import SimpleCookie
        c = SimpleCookie()
        c.load(cookie_str)
        for key, morsel in c.items():
            client.cookies.set(key, morsel.value)

    auth_url = config.get("auth.auth_url", "")
    if auth_url:
        auth_data = config.get("auth.auth_data", "")
        if not auth_data:
            username = config.get("auth.auth_username", "")
            password = config.get("auth.auth_password", "")
            if username and password:
                auth_data = f"username={username}&password={password}"
        if auth_data:
            await client.post(auth_url, data=auth_data)

    return client


_LOGGER_INITIALIZED: set = set()


def get_logger(name: str) -> logging.Logger:
    """获取指定名称的 logger，并配置 VulnForge 标准格式的 handler。

    格式: [YYYY-MM-DD HH:MM:SS] LEVEL  name - message
    同一 name 只会添加一次 handler。
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    if name not in _LOGGER_INITIALIZED:
        _LOGGER_INITIALIZED.add(name)

        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)

        formatter = logging.Formatter(
            "[%(asctime)s] %(levelname)-7s %(name)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.propagate = False

    return logger


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
