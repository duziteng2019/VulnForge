"""Nuclei 模板引擎集成 — 接入社区数千POC模板"""

import asyncio
import json
import logging
import os
import subprocess
from pathlib import Path

from ..core.config import VulnForgeConfig
from ..core.target import Target


# Nuclei模板目录
NUCLEI_TEMPLATES_DIR = os.path.expanduser("~/nuclei-templates")


class NucleiRunner:
    """Nuclei扫描执行器"""

    def __init__(self, config: VulnForgeConfig, target: Target):
        self.config = config
        self.target = target
        self.templates_dir = NUCLEI_TEMPLATES_DIR
        self.logger = logging.getLogger(__name__)

    async def run(
        self,
        output_dir: Path,
        severity: str = "medium,high,critical",
        tags: str = "",
    ) -> dict:
        """执行Nuclei扫描

        Args:
            output_dir: 输出目录
            severity: 漏洞严重级别过滤
            tags: 按标签过滤（如 "sql,xss,ssrf"）

        Returns:
            扫描结果字典
        """
        if not os.path.exists(self.templates_dir):
            return {
                "status": "skipped",
                "message": "Nuclei模板未安装，请先运行: nuclei -update-templates",
                "findings": [],
            }

        if not self._check_nuclei_installed():
            return {
                "status": "skipped",
                "message": "Nuclei未安装，请先安装",
                "findings": [],
            }

        result_file = output_dir / "nuclei_results.json"
        cmd = self._build_command(str(result_file), severity, tags)

        self.logger.info("Nuclei扫描中 (severity=%s)...", severity)
        self.logger.info("命令: %s ...", " ".join(cmd[:6]))

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=300
            )

            # 解析结果
            findings = self._parse_results(result_file)

            self.logger.info("Nuclei发现 %d 个漏洞", len(findings))

            return {
                "status": "completed",
                "findings": findings,
                "total": len(findings),
                "stdout": stdout.decode(errors="ignore")[-500:],
                "stderr": stderr.decode(errors="ignore")[-500:],
            }

        except asyncio.TimeoutError:
            self.logger.warning("Nuclei扫描超时")
            return {"status": "timeout", "findings": []}
        except Exception as e:
            self.logger.error("Nuclei扫描出错: %s", e)
            return {"status": "error", "error": str(e), "findings": []}

    def _build_command(
        self, result_file: str, severity: str, tags: str
    ) -> list[str]:
        """构建nuclei命令"""
        cmd = [
            "nuclei",
            "-u", self.target.url,
            "-severity", severity,
            "-jsonl", "-o", result_file,
            "-timeout", "8",
            "-concurrency", "15",
            "-rate-limit", "50",
            "-no-color",
            "-disable-update-check",
        ]

        if tags:
            cmd.extend(["-tags", tags])

        # 限制扫描范围：优先扫http协议模板
        http_templates = f"{self.templates_dir}/http/"
        if os.path.isdir(http_templates):
            cmd.extend(["-t", http_templates])
        else:
            self.logger.warning(
                "未找到 http 协议模板目录 (%s)，回退到扫描全部模板",
                http_templates,
            )

        # 限制严重级别
        cmd.extend(["-severity", "critical,high,medium"])
        # 超时控制
        cmd.extend(["-max-host-error", "5"])

        return cmd

    def _parse_results(self, result_file: Path) -> list[dict]:
        """解析Nuclei JSON结果"""
        if not result_file.exists() or result_file.stat().st_size == 0:
            return []

        findings = []
        with open(result_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    finding = {
                        "vuln_type": f"nuclei/{data.get('template-id', 'unknown')}",
                        "name": data.get("info", {}).get("name", ""),
                        "url": data.get("matched-at", ""),
                        "severity": data.get("info", {}).get("severity", "medium"),
                        "description": data.get("info", {}).get("description", ""),
                        "reference": data.get("info", {}).get("reference", ""),
                        "tags": data.get("info", {}).get("tags", []),
                        "matched": data.get("matched-at", ""),
                        "template_id": data.get("template-id", ""),
                        "type": data.get("type", ""),
                        "extracted_results": data.get("extracted-results", []),
                        "curl_command": data.get("curl-command", ""),
                        "source": "nuclei",
                    }
                    findings.append(finding)
                except json.JSONDecodeError:
                    continue

        return findings

    def _check_nuclei_installed(self) -> bool:
        """检查nuclei是否已安装"""
        try:
            result = subprocess.run(
                ["nuclei", "-version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    @staticmethod
    def get_template_stats() -> dict:
        """获取模板统计信息"""
        templates_dir = NUCLEI_TEMPLATES_DIR
        if not os.path.exists(templates_dir):
            return {"total": 0, "categories": {}}

        categories = {}
        total = 0
        for root, dirs, files in os.walk(templates_dir):
            for f in files:
                if f.endswith(".yaml") or f.endswith(".yml"):
                    total += 1
                    rel_path = os.path.relpath(root, templates_dir)
                    category = rel_path.split("/")[0] if rel_path else "other"
                    categories[category] = categories.get(category, 0) + 1

        return {"total": total, "categories": categories}
