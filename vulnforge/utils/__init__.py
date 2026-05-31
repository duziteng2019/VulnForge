"""工具函数"""

import re
import socket
from urllib.parse import urlparse


def is_valid_url(url: str) -> bool:
    """检查URL是否合法"""
    try:
        parsed = urlparse(url)
        return all([parsed.scheme, parsed.netloc])
    except Exception:
        return False


def sanitize_filename(name: str) -> str:
    """清理文件名"""
    return re.sub(r"[^\w\-_.]", "_", name)


def get_local_ip() -> str:
    """获取本机IP"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def chunk_list(lst: list, size: int):
    """将列表分块"""
    for i in range(0, len(lst), size):
        yield lst[i:i + size]


SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 7,
    "medium": 5,
    "low": 2,
    "info": 1,
}


def score_target(findings: list) -> dict:
    """对目标进行安全评分（0-100，越高越不安全）"""
    if not findings:
        return {"score": 0, "level": "safe", "detail": "未发现安全漏洞"}

    total = sum(SEVERITY_WEIGHTS.get(f.get("severity", "low"), 1) for f in findings)
    score = min(100, total * 5)

    if score >= 70:
        level = "danger"
    elif score >= 40:
        level = "warning"
    elif score >= 10:
        level = "attention"
    else:
        level = "safe"

    return {
        "score": score,
        "level": level,
        "total_findings": len(findings),
        "detail": f"安全评分 {score}/100 — {'高风险' if score >= 40 else '低风险'}",
    }
