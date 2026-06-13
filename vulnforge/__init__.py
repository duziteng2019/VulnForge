"""VulnForge — AI驱动的自动化漏洞挖掘框架"""

try:
    from importlib.metadata import version as _version
    __version__ = _version("vulnforge")
except Exception:
    __version__ = "0.2.0"

__all__ = ["__version__"]
