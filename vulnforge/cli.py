"""VulnForge CLI入口"""

import asyncio
import json
import os
import sys
from pathlib import Path

import click

from . import __version__
from .core.engine import ScanEngine
from .core.config import VulnForgeConfig, DEFAULT_CONFIG_PATH


@click.group()
@click.version_option(version=__version__, prog_name="VulnForge")
def main():
    """🛡️ VulnForge — AI驱动的自动化漏洞挖掘框架"""
    pass


@main.command()
@click.argument("targets", required=True)
@click.option("-m", "--mode", type=click.Choice(["full", "recon-only", "scan-only", "analyze-only"]), default="full", help="扫描模式")
@click.option("-o", "--output", type=click.Choice(["md", "json", "html"]), default="md", help="输出格式")
@click.option("--config", type=click.Path(), help="配置文件路径")
@click.option("--verbose", is_flag=True, help="详细输出")
@click.option("--concurrent", default=3, help="批量扫描并发数（默认3）")
def scan(targets: str, mode: str, output: str, config: str, verbose: bool, concurrent: int):
    """🔍 对目标URL进行自动化漏洞扫描

    支持单个目标或批量扫描（传入文件路径或逗号分隔列表）
    """
    # 解析目标列表
    target_list = _resolve_targets(targets)
    if not target_list:
        click.echo("❌ 未找到有效的扫描目标")
        sys.exit(1)

    is_batch = len(target_list) > 1

    if is_batch:
        click.echo(f"🛡️  VulnForge v{__version__} — 批量扫描模式")
        click.echo(f"🎯  共 {len(target_list)} 个目标")
        click.echo(f"⚙️   并发: {concurrent}")
        click.echo("")

    cfg = VulnForgeConfig.load(config) if config else VulnForgeConfig.load()

    if not cfg.get("api_key") and mode in ("full", "analyze-only"):
        click.echo("⚠️  未配置AI API Key，将使用本地规则分析（功能受限）")
        click.echo("")

    engine = ScanEngine(cfg)

    if is_batch:
        # 批量扫描
        import asyncio as _asyncio
        sem = _asyncio.Semaphore(concurrent)

        async def scan_one(target_url: str, idx: int) -> dict:
            async with sem:
                click.echo(f"[{idx}/{len(target_list)}] 🔍 {target_url}")
                try:
                    return await engine.run(target_url, mode)
                except Exception as e:
                    click.echo(f"  [!] 扫描失败: {e}")
                    return {"summary": {"target": target_url, "error": str(e)}}

        async def run_batch():
            tasks = [scan_one(t, i + 1) for i, t in enumerate(target_list)]
            return await _asyncio.gather(*tasks)

        all_results = asyncio.run(run_batch())

        # 汇总
        total_vulns = sum(
            r.get("scanner", {}).get("total", 0) or 0
            for r in all_results
        )
        click.echo(f"\n{'='*50}")
        click.echo(f"📊 批量扫描完成")
        click.echo(f"{'='*50}")
        click.echo(f"  总计: {len(target_list)} 目标, {total_vulns} 漏洞")

        # 按漏洞数排序输出
        sorted_results = sorted(
            all_results,
            key=lambda r: r.get("scanner", {}).get("total", 0) or 0,
            reverse=True,
        )
        click.echo(f"\n{'目标':<40} {'漏洞数':<8} {'状态'}")
        click.echo("-" * 60)
        for r in sorted_results:
            target_url = r.get("summary", {}).get("target", "?")
            vulns = r.get("scanner", {}).get("total", 0) or 0
            status = "✓" if not r.get("summary", {}).get("error") else "✗"
            click.echo(f"{target_url:<40} {vulns:<8} {status}")

    else:
        # 单个扫描
        click.echo(f"🛡️  VulnForge v{__version__}")
        click.echo(f"🎯  Target: {target_list[0]}")
        click.echo(f"⚙️   Mode: {mode}")
        click.echo("")

        try:
            results = asyncio.run(engine.run(target_list[0], mode))
        except KeyboardInterrupt:
            click.echo("\n⚠️  扫描被用户中断")
            sys.exit(1)

        # 输出结果
        _print_scan_results(results, cfg, output)


def _resolve_targets(targets_str: str) -> list[str]:
    """解析目标参数，支持文件/逗号分隔/单URL"""
    targets_str = targets_str.strip()

    # 如果是文件路径
    if os.path.isfile(targets_str):
        with open(targets_str, "r", encoding="utf-8") as f:
            targets = [
                line.strip() for line in f
                if line.strip() and not line.startswith("#")
            ]
        return targets

    # 如果是逗号分隔
    if "," in targets_str:
        return [t.strip() for t in targets_str.split(",") if t.strip()]

    # 单URL
    return [targets_str]


def _print_scan_results(results: dict, cfg: VulnForgeConfig, output: str):
    """打印扫描结果"""
    summary = results.get("summary", {})
    findings = results.get("scanner", {}).get("findings", [])
    report = results.get("ai", {}).get("report", "")

    click.echo("\n" + "=" * 50)
    click.echo("📊 扫描总结")
    click.echo("=" * 50)
    click.echo(f"  漏洞总数: {len(findings)}")
    if results.get("scanner", {}).get("severity_counts"):
        for sev, cnt in results["scanner"]["severity_counts"].items():
            if cnt > 0:
                click.echo(f"    {sev}: {cnt}")
    click.echo(f"  扫描耗时: {summary.get('elapsed_seconds', 0)}s")

    if report and output == "md":
        scan_id = summary.get("scan_id", "latest")
        output_dir = Path(cfg.output_dir) / scan_id
        report_path = output_dir / "report.md"
        click.echo(f"\n📝 报告已保存: {report_path}")
        lines = report.split("\n")
        for line in lines[:30]:
            click.echo(line)
        if len(lines) > 30:
            click.echo("...(完整报告请查看文件)")
        click.echo("-" * 50)


@main.group()
def config():
    """⚙️  配置管理"""
    pass


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key: str, value: str):
    """设置配置项"""
    cfg = VulnForgeConfig.load()
    cfg.set(key, value)
    click.echo(f"✓ 已设置 {key} = {value}")


@config.command("get")
@click.argument("key", required=False)
@click.option("--json", "output_json", is_flag=True, help="JSON格式输出")
def config_get(key: str, output_json: bool):
    """查看配置"""
    cfg = VulnForgeConfig.load()
    if key:
        value = cfg.get(key)
        if output_json:
            click.echo(json.dumps({key: value}, ensure_ascii=False, indent=2))
        else:
            click.echo(f"{key} = {value}")
    else:
        if output_json:
            click.echo(json.dumps(cfg.data, ensure_ascii=False, indent=2))
        else:
            for k, v in cfg.data.items():
                if not isinstance(v, dict):
                    click.echo(f"{k} = {v}")
                else:
                    click.echo(f"\n[{k}]")
                    for sk, sv in v.items():
                        click.echo(f"  {sk} = {sv}")


@config.command("list")
def config_list():
    """列出所有配置"""
    cfg = VulnForgeConfig.load()
    click.echo(json.dumps(cfg.data, ensure_ascii=False, indent=2))


@config.command("init")
def config_init():
    """初始化默认配置"""
    cfg = VulnForgeConfig.load()
    cfg.save()
    click.echo(f"✓ 配置文件已初始化: {DEFAULT_CONFIG_PATH}")
    click.echo("   请使用 'vulnforge config set api_key <your-key>' 配置AI密钥")


@main.command()
@click.option("--limit", default=10, help="显示最近N条记录")
def history(limit: int):
    """📜 查看扫描历史"""
    cfg = VulnForgeConfig.load()
    scans_dir = Path(cfg.output_dir)

    if not scans_dir.exists():
        click.echo("暂无扫描记录")
        return

    scan_dirs = sorted(scans_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]

    click.echo(f"📜 最近 {len(scan_dirs)} 条扫描记录:")
    click.echo(f"{'Scan ID':<22} {'目标':<40} {'漏洞':<6} {'时间'}")
    click.echo("-" * 80)

    for scan_dir in scan_dirs:
        if not scan_dir.is_dir():
            continue
        result_file = scan_dir / "results.json"
        if result_file.exists():
            try:
                with open(result_file, "r") as f:
                    data = json.load(f)
                summary = data.get("summary", {})
                target = summary.get("target", "?")
                total_vulns = summary.get("total_vulnerabilities", 0)
                scan_id = summary.get("scan_id", scan_dir.name)
                click.echo(f"{scan_id:<22} {target:<40} {total_vulns:<6}")
            except Exception:
                continue


@main.command()
@click.argument("scan_id")
def show(scan_id: str):
    """📋 查看某次扫描详情"""
    cfg = VulnForgeConfig.load()
    result_file = Path(cfg.output_dir) / scan_id / "results.json"

    if not result_file.exists():
        click.echo(f"❌ 未找到扫描记录: {scan_id}")
        return

    with open(result_file, "r") as f:
        data = json.load(f)

    click.echo(json.dumps(data, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
