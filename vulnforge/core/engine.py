"""VulnForge 核心引擎 — 全流程调度器"""

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Optional
from datetime import datetime

import httpx

from .config import VulnForgeConfig, create_authenticated_client
from .target import Target
from ..utils.oob import OOBDetector

logger = logging.getLogger(__name__)


class EmptyReport:
    pass


class ScanEngine:
    """主扫描引擎，编排各阶段执行"""

    def __init__(self, config: Optional[VulnForgeConfig] = None):
        self.config = config or VulnForgeConfig.load()
        self.logger = logging.getLogger(__name__)
        self.target: Optional[Target] = None
        self.scan_id: str = ""
        self.start_time: float = 0.0
        self.output_dir: Optional[Path] = None
        self.semaphore = asyncio.Semaphore(self.config.get("max_concurrent", 5))
        self.results: dict = {
            "recon": {},
            "scanner": {},
            "ai": {},
            "summary": {},
        }

    async def run(self, target_url: str, mode: str = "full") -> dict:
        """执行全链路扫描"""
        self.scan_id = f"scan_{int(time.time())}"
        self.target = Target(target_url)
        self.start_time = time.time()

        self.output_dir = Path(self.config.output_dir) / self.scan_id
        self.output_dir.mkdir(parents=True, exist_ok=True)

        timeout = self.config.get("timeout", 30)
        self.logger.info("VulnForge 启动 | 目标: %s | 模式: %s", target_url, mode)
        self.logger.info("Scan ID: %s", self.scan_id)

        stages = []
        if mode in ("full", "recon-only"):
            stages.append("recon")
        if mode in ("full", "scan-only"):
            stages.append("scanner")
        if mode in ("full", "analyze-only"):
            stages.append("ai")

        client = await create_authenticated_client(self.config, timeout=timeout)

        # OOB 检测器初始化
        oob = None
        if self.config.get("oob.enabled", True):
            oob_domain = self.config.get("oob.domain", "")
            oob = OOBDetector(scan_id=self.scan_id, callback_domain=oob_domain)
            await oob.register(oob_domain)
            self.logger.info("OOB 检测已启用 | 回调域名: %s", oob.callback_full)

        try:
            for stage in stages:
                self.logger.info("阶段: %s", stage)
                try:
                    if stage == "recon":
                        self.results["recon"] = await self._run_recon(self.output_dir, client)
                    elif stage == "scanner":
                        self.results["scanner"] = await self._run_scanner(self.output_dir, client, oob=oob)
                    elif stage == "ai":
                        self.results["ai"] = await self._run_ai_analysis(self.output_dir, client)
                except Exception as e:
                    self.logger.error("阶段 %s 出错: %s", stage, e)
                    self.results[stage] = {"error": str(e)}
        finally:
            await client.aclose()

        # OOB 轮询 — 等待回调
        if oob and self.config.get("oob.enabled", True):
            self.logger.info("OOB 轮询等待回调...")
            oob_findings = await oob.poll()
            if oob_findings:
                self.results["oob"] = {"findings": oob_findings}
                self.logger.info("OOB 回调发现 %d 个结果", len(oob_findings))
            else:
                self.logger.info("OOB 未检测到回调")

        # 生成总结
        elapsed = time.time() - self.start_time
        self.results["summary"] = self._build_summary(elapsed)

        # 保存结果
        self._save_results(self.output_dir)

        self.logger.info("扫描完成 | 耗时: %.1fs | 结果: %s", elapsed, self.output_dir)
        return self.results

    async def _run_recon(self, output_dir: Path, client: httpx.AsyncClient) -> dict:
        """信息收集阶段"""
        from ..recon import ReconRunner
        runner = ReconRunner(self.config, self.target)
        return await runner.run(output_dir)

    async def _run_scanner(self, output_dir: Path, client: httpx.AsyncClient, oob=None) -> dict:
        """漏洞扫描阶段"""
        from ..scanner import ScannerRunner
        runner = ScannerRunner(self.config, self.target, client=client, oob=oob)
        recon_results = self.results.get("recon", {})
        return await runner.run(output_dir, client=client, recon_results=recon_results)

    async def _run_ai_analysis(self, output_dir: Path, client: httpx.AsyncClient) -> dict:
        """AI分析阶段"""
        from ..ai import AIAnalyzer
        analyzer = AIAnalyzer(self.config, self.target, client=client)
        return await analyzer.run(output_dir, self.results)

    def _build_summary(self, elapsed: float) -> dict:
        """构建扫描总结"""
        return {
            "scan_id": self.scan_id,
            "target": str(self.target.url) if self.target else "",
            "start_time": datetime.fromtimestamp(self.start_time).isoformat(),
            "elapsed_seconds": round(elapsed, 1),
            "recon_status": len(self.results.get("recon", {})) > 0,
            "scanner_status": len(self.results.get("scanner", {})) > 0,
            "ai_status": len(self.results.get("ai", {})) > 0,
            "total_vulnerabilities": len(
                self.results.get("scanner", {}).get("findings", [])
            ) + len(
                self.results.get("ai", {}).get("findings", [])
            ),
        }

    def _save_results(self, output_dir: Path) -> None:
        """持久化扫描结果"""
        result_file = output_dir / "results.json"
        with open(result_file, "w", encoding="utf-8") as f:
            json.dump(self.results, f, ensure_ascii=False, indent=2, default=str)
