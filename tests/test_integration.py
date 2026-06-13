"""
VulnForge 集成测试
"""

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest


def test_cli_help():
    """验证CLI帮助正常"""
    from click.testing import CliRunner
    from vulnforge.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "VulnForge" in result.output or "vulnforge" in result.output


def test_cli_scan_missing_target():
    """验证缺少目标的错误提示"""
    from click.testing import CliRunner
    from vulnforge.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["scan"])
    assert result.exit_code != 0


def test_config_validate_local():
    """验证无API Key时的本地fallback"""
    from vulnforge.core.config import VulnForgeConfig

    cfg = VulnForgeConfig({"api_key": ""})
    assert cfg.get("api_key") == ""


@pytest.mark.asyncio
async def test_scanner_dedup():
    """验证扫描器去重逻辑"""
    from vulnforge.scanner.scanner import ScannerRunner, Finding
    from vulnforge.core.config import VulnForgeConfig
    from vulnforge.core.target import Target

    cfg = VulnForgeConfig({"api_key": ""})
    target = Target("http://test.com")
    runner = ScannerRunner(cfg, target)

    # 添加两次相同的finding
    f1 = Finding("xss", "http://test.com", "q", "<script>", "medium", "evidence", "desc")
    f2 = Finding("xss", "http://test.com", "q", "<script>", "medium", "evidence", "desc")

    runner._add_finding(f1)
    runner._add_finding(f2)

    assert len(runner.findings) == 1
    assert len(runner._seen) == 1
