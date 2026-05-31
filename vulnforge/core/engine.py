"""VulnForge 核心引擎 — 全流程调度器"""

import asyncio
import json
import time
from pathlib import Path
from typing import Optional
from datetime import datetime

from .config import VulnForgeConfig
from .target import Target

# Type stub for modules loaded dynamically
class EmptyReport:
    pass


class ScanEngine:
    """主扫描引擎，编排各阶段执行"""

    def __init__(self, config: Optional[VulnForgeConfig] = None):
        self.config = config or VulnForgeConfig.load()
        self.target: Optional[Target] = None
        self.scan_id: str = ""
        self.start_time: float = 0.0
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

        output_dir = Path(self.config.output_dir) / self.scan_id
        output_dir.mkdir(parents=True, exist_ok=True)

        print(f"[*] VulnForge 启动 | 目标: {target_url} | 模式: {mode}")
        print(f"[*] Scan ID: {self.scan_id}")

        stages = []
        if mode in ("full", "recon-only"):
            stages.append("recon")
        if mode in ("full", "scan-only"):
            stages.append("scanner")
        if mode in ("full", "analyze-only"):
            stages.append("ai")

        for stage in stages:
            print(f"\n[→] 阶段: {stage}")
            try:
                if stage == "recon":
                    self.results["recon"] = await self._run_recon(output_dir)
                elif stage == "scanner":
                    self.results["scanner"] = await self._run_scanner(output_dir)
                elif stage == "ai":
                    self.results["ai"] = await self._run_ai_analysis(output_dir)
            except Exception as e:
                print(f"[!] 阶段 {stage} 出错: {e}")
                self.results[stage] = {"error": str(e)}

        # 生成总结
        elapsed = time.time() - self.start_time
        self.results["summary"] = self._build_summary(elapsed)

        # 保存结果
        self._save_results(output_dir)

        print(f"\n[✓] 扫描完成 | 耗时: {elapsed:.1f}s | 结果: {output_dir}")
        return self.results

    async def _run_recon(self, output_dir: Path) -> dict:
        """信息收集阶段"""
        from ..recon import ReconRunner
        runner = ReconRunner(self.config, self.target)
        return await runner.run(output_dir)

    async def _run_scanner(self, output_dir: Path) -> dict:
        """漏洞扫描阶段"""
        from ..scanner import ScannerRunner
        runner = ScannerRunner(self.config, self.target)
        return await runner.run(output_dir)

    async def _run_ai_analysis(self, output_dir: Path) -> dict:
        """AI分析阶段"""
        from ..ai import AIAnalyzer
        analyzer = AIAnalyzer(self.config, self.target)
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
