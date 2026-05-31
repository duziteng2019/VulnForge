"""数据格式化工具"""

import json
from datetime import datetime


def format_timestamp(ts: float) -> str:
    """格式化时间戳"""
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def truncate(text: str, max_length: int = 100) -> str:
    """截断文本"""
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def pretty_json(data: dict) -> str:
    """格式化JSON"""
    return json.dumps(data, ensure_ascii=False, indent=2, default=str)


def severity_emoji(severity: str) -> str:
    """严重级别转emoji"""
    emojis = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
        "info": "ℹ️",
    }
    return emojis.get(severity, "⚪")
