"""SARIF 报告生成器 — GitHub Code Scanning 兼容格式"""

import json
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemas/sarif-schema-2.1.0.json"


def severity_to_sarif_level(severity: str) -> str:
    """将 VulnForge severity 映射为 SARIF 等级"""
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    return mapping.get(severity, "none")


class SARIFReport:
    """SARIF 格式报告生成器"""

    def __init__(self, tool_name: str = "VulnForge", tool_version: str = "0.2.0"):
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.results: list[dict] = []
        self.rules: dict[str, dict] = {}

    def add_result(
        self,
        vuln_type: str,
        url: str,
        severity: str,
        message: str,
        evidence: str = "",
        param: str = "",
        payload: str = "",
    ):
        """添加一个发现到 SARIF 结果集"""
        rule_id = vuln_type.upper()

        # 规则去重注册
        if rule_id not in self.rules:
            self.rules[rule_id] = {
                "id": rule_id,
                "name": vuln_type,
                "shortDescription": {"text": message[:200]},
                "fullDescription": {"text": message},
                "defaultConfiguration": {"level": severity_to_sarif_level(severity)},
                "properties": {"tags": ["security", vuln_type]},
            }

        result = {
            "ruleId": rule_id,
            "ruleIndex": len(self.rules) - 1 if rule_id not in list(self.rules.keys())[:-1] else list(self.rules.keys()).index(rule_id),
            "level": severity_to_sarif_level(severity),
            "message": {"text": message[:500]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": url},
                        "region": {
                            "startLine": 1,
                            "snippet": {"text": param or url},
                        },
                    }
                }
            ],
        }

        # 证据和 payload 加到 properties
        props = {}
        if evidence:
            props["evidence"] = evidence[:200]
        if payload:
            props["payload"] = payload[:200]
        if param:
            props["parameter"] = param
        if props:
            result["properties"] = props

        self.results.append(result)

    def add_scan_summary(self, scan_id: str, target_url: str, elapsed: float, total_vulns: int):
        """添加扫描摘要信息"""
        self.scan_info = {
            "scan_id": scan_id,
            "target": target_url,
            "elapsed_seconds": round(elapsed, 1),
            "total_vulnerabilities": total_vulns,
            "timestamp": datetime.now().isoformat(),
        }

    def generate(self) -> dict:
        """生成完整的 SARIF JSON"""
        sarif = {
            "$schema": SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "informationUri": "https://github.com/duziteng2019/VulnForge",
                            "rules": list(self.rules.values()),
                        }
                    },
                    "results": self.results,
                    "columnKind": "utf16CodeUnits",
                    "properties": {
                        "scanInfo": getattr(self, "scan_info", {}),
                    },
                }
            ],
        }
        return sarif

    def to_json(self, indent: int = 2) -> str:
        """输出 SARIF JSON 字符串"""
        return json.dumps(self.generate(), ensure_ascii=False, indent=indent)

    def save(self, output_path: str) -> None:
        """保存 SARIF 到文件"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(self.to_json())
        logger.info("SARIF 报告已保存: %s", output_path)
