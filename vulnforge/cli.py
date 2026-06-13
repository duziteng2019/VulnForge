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
@click.option("--cookie", help="Cookie字符串 (如 'SESSION=abc123; token=xyz')")
@click.option("--auth-url", help="登录URL，用于自动获取Cookie")
@click.option("--auth-data", help="登录POST数据 (如 'username=admin&password=xxx')")
@click.option("--auth-username", help="登录用户名")
@click.option("--auth-password", help="登录密码")
@click.option("--oob-domain", help="OOB 回调域名 (如 oast.fun, 或自定义域名)")
@click.option("--fuzz", is_flag=True, help="启用参数模糊测试（响应差异分析）")
@click.option("--sarif", is_flag=True, help="输出 SARIF 格式报告（GitHub Code Scanning 兼容）")
@click.option("--fail-on", default="", help="漏洞级别达到此值则 exit 1 (如 'high,critical')")
@click.option("--ws/--no-ws", default=True, help="启用/禁用 WebSocket 安全测试")
@click.option("--ssti/--no-ssti", default=True, help="启用/禁用 SSTI 模板注入检测")
@click.option("--redirect/--no-redirect", default=True, help="启用/禁用 Open Redirect 检测")
def scan(targets: str, mode: str, output: str, config: str, verbose: bool, concurrent: int, cookie: str, auth_url: str, auth_data: str, auth_username: str, auth_password: str, oob_domain: str, fuzz: bool, sarif: bool, fail_on: str, ws: bool, ssti: bool, redirect: bool):
    """🔍 对目标URL进行自动化漏洞扫描"""
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

    # 设置 auth 参数（如有）
    if cookie:
        cfg.set("auth.cookie", cookie)
    if auth_url:
        cfg.set("auth.auth_url", auth_url)
    if auth_data:
        cfg.set("auth.auth_data", auth_data)
    if auth_username:
        cfg.set("auth.auth_username", auth_username)
    if auth_password:
        cfg.set("auth.auth_password", auth_password)
    if oob_domain:
        cfg.set("oob.domain", oob_domain)
    if fuzz:
        cfg.set("scanner.enable_fuzzing", True)
    cfg.set("scanner.enable_websocket", ws)
    cfg.set("scanner.enable_ssti", ssti)
    cfg.set("scanner.enable_redirect", redirect)

    if not cfg.get("api_key") and mode in ("full", "analyze-only"):
        click.echo("⚠️  未配置AI API Key，将使用本地规则分析（功能受限）")
        click.echo("")

    engine = ScanEngine(cfg)

    if is_batch:
        sem = asyncio.Semaphore(concurrent)

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
            return await asyncio.gather(*tasks)

        all_results = asyncio.run(run_batch())

        total_vulns = sum(
            r.get("scanner", {}).get("total", 0) or 0
            for r in all_results
        )
        click.echo(f"\n{'='*50}")
        click.echo(f"📊 批量扫描完成")
        click.echo(f"{'='*50}")
        click.echo(f"  总计: {len(target_list)} 目标, {total_vulns} 漏洞")

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
        click.echo(f"🛡️  VulnForge v{__version__}")
        click.echo(f"🎯  Target: {target_list[0]}")
        click.echo(f"⚙️   Mode: {mode}")
        click.echo("")

        try:
            results = asyncio.run(engine.run(target_list[0], mode))
        except KeyboardInterrupt:
            click.echo("\n⚠️  扫描被用户中断")
            sys.exit(1)

        _print_scan_results(results, cfg, output)

        # SARIF 输出
        if sarif:
            _save_sarif_report(results, cfg, target_list[0])

        # Exit code 策略
        if fail_on:
            _check_fail_on(results, fail_on)


def _resolve_targets(targets_str: str) -> list[str]:
    """解析目标参数"""
    targets_str = targets_str.strip()
    if os.path.isfile(targets_str):
        with open(targets_str, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    if "," in targets_str:
        return [t.strip() for t in targets_str.split(",") if t.strip()]
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


def _save_sarif_report(results: dict, cfg, target_url: str) -> None:
    """保存 SARIF 格式报告"""
    from .utils.sarif import SARIFReport

    summary = results.get("summary", {})
    findings = results.get("scanner", {}).get("findings", [])
    scan_id = summary.get("scan_id", "scan_latest")

    report = SARIFReport(tool_version=__version__)
    for f in findings:
        report.add_result(
            vuln_type=f.get("vuln_type", "unknown"),
            url=f.get("url", target_url),
            severity=f.get("severity", "medium"),
            message=f.get("description", ""),
            evidence=f.get("evidence", ""),
            param=f.get("param", ""),
            payload=f.get("payload", ""),
        )

    report.add_scan_summary(
        scan_id=scan_id,
        target_url=target_url,
        elapsed=summary.get("elapsed_seconds", 0),
        total_vulns=summary.get("total_vulnerabilities", 0),
    )

    output_dir = Path(cfg.output_dir) / scan_id
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "report.sarif"
    report.save(str(output_path))
    click.echo(f"\n📊 SARIF 报告已保存: {output_path}")


def _check_fail_on(results: dict, fail_on: str) -> None:
    """检查是否满足 exit 1 条件"""
    fail_levels = set(sev.strip().lower() for sev in fail_on.split(","))
    findings = results.get("scanner", {}).get("findings", [])

    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    max_found = 0
    for f in findings:
        sev = f.get("severity", "info").lower()
        max_found = max(max_found, severity_order.get(sev, 0))

    for level in fail_levels:
        if level in severity_order and severity_order[level] <= max_found:
            click.echo(f"\n⚠️  存在 {level} 级别漏洞，--fail-on 策略触发，exit 1")
            sys.exit(1)

    click.echo(f"✓ 漏洞级别均未达到 --fail-on={fail_on} 阈值")


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


@main.group()
def plugin():
    """🔌 插件管理"""
    pass


@plugin.command("list")
def plugin_list():
    """列出已安装插件"""
    from .utils.plugin import PluginManager
    mgr = PluginManager()
    plugins = mgr.list_plugins()
    if not plugins:
        click.echo("未安装任何插件")
        return
    click.echo(f"{'名称':<20} {'类型':<10} {'版本':<8} {'描述'}")
    click.echo("-" * 60)
    for p in plugins:
        click.echo(f"{p['name']:<20} {p['type']:<10} {p['version']:<8} {p['description']}")


@plugin.command("install")
@click.argument("path")
def plugin_install(path: str):
    """安装插件（从 .py 文件）"""
    from .utils.plugin import PluginManager
    mgr = PluginManager()
    if mgr.install(path):
        click.echo(f"✓ 插件安装成功: {path}")
    else:
        click.echo(f"✗ 插件安装失败: {path}")


@plugin.command("uninstall")
@click.argument("name")
def plugin_uninstall(name: str):
    """卸载插件"""
    from .utils.plugin import PluginManager
    mgr = PluginManager()
    if mgr.uninstall(name):
        click.echo(f"✓ 插件已卸载: {name}")
    else:
        click.echo(f"✗ 插件卸载失败: {name}")


if __name__ == "__main__":
    main()
