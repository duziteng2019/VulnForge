"""VulnForge 基础测试"""

def test_import():
    """验证模块可正常导入"""
    from vulnforge import __version__
    assert isinstance(__version__, str)
    assert len(__version__) > 0


def test_config_defaults():
    """验证配置默认值"""
    from vulnforge.core.config import VulnForgeConfig, DEFAULT_CONFIG

    cfg = VulnForgeConfig.load()
    assert cfg.get("ai_provider") == "deepseek"
    assert cfg.get("max_concurrent") == 5
    assert cfg.get("recon.enable_subdomain") is True


def test_config_get_set():
    """验证配置读写"""
    from vulnforge.core.config import VulnForgeConfig

    cfg = VulnForgeConfig({"test_key": "test_val", "nested": {"key": "val"}})
    assert cfg.get("test_key") == "test_val"
    assert cfg.get("nested.key") == "val"
    assert cfg.get("nonexistent", "default") == "default"


def test_target_parsing():
    """验证目标解析"""
    from vulnforge.core.target import Target

    t = Target("https://example.com/path/to/page")
    assert t.domain == "example.com"
    assert t.scheme == "https"
    assert t.base_url == "https://example.com"

    t2 = Target("example.com")
    assert t2.domain == "example.com"
    assert t2.scheme == "https"


def test_target_is_ip():
    """验证IP检测"""
    from vulnforge.core.target import Target

    assert Target("http://192.168.1.1").is_ip is True
    assert Target("https://example.com").is_ip is False


def test_target_resolve_path():
    """验证路径拼接"""
    from vulnforge.core.target import Target

    t = Target("https://example.com/api")
    assert t.resolve_path("/admin") == "https://example.com/admin"
    assert t.resolve_path("login") == "https://example.com/login"


def test_validate_api_key():
    """验证API Key格式校验"""
    from vulnforge.core.config import validate_api_key

    assert validate_api_key("sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") is True
    assert validate_api_key("") is False
    assert validate_api_key(None) is False
    assert validate_api_key("   ") is False
    assert validate_api_key("invalid key with spaces") is False


def test_finding_class():
    """验证漏洞发现对象"""
    from vulnforge.scanner.scanner import Finding

    f = Finding("sql_injection", "http://test.com", "id", "' OR '1'='1",
                "high", "error match", "desc")
    d = f.to_dict()
    assert d["vuln_type"] == "sql_injection"
    assert d["severity"] == "high"
    assert d["param"] == "id"
    assert d["payload"] == "' OR '1'='1"


def test_format_utils():
    """验证格式化工具"""
    from vulnforge.utils.format import truncate, severity_emoji

    assert truncate("hello world", 5) == "he..."
    assert truncate("short", 20) == "short"
    assert severity_emoji("critical") == "🔴"
    assert severity_emoji("high") == "🟠"
    assert severity_emoji("info") == "ℹ️"
