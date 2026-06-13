"""VulnForge 插件系统 — 基础类、加载器、管理器"""

import importlib
import importlib.util
import inspect
import logging
import os
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

PLUGIN_DIRS = [
    Path.home() / ".vulnforge" / "plugins",
    Path.cwd() / "plugins",
]


class VulnForgePlugin:
    """插件基类 — 所有自定义插件必须继承此类"""

    # 插件元数据（子类覆盖）
    name: str = ""
    description: str = ""
    version: str = "1.0.0"
    plugin_type: str = "scanner"  # recon | scanner | analyzer | report
    author: str = ""
    dependencies: list[str] = []

    def __init__(self):
        self.logger = logging.getLogger(f"plugin.{self.name}")
        self.config = None
        self.target = None

    async def initialize(self, config, target) -> None:
        """插件初始化（加载时调用）

        Args:
            config: VulnForgeConfig 实例
            target: Target 实例
        """
        self.config = config
        self.target = target
        self.logger.info("插件已加载: %s v%s", self.name, self.version)

    async def run(self, **kwargs) -> list:
        """插件主逻辑 — 子类必须实现

        Args:
            **kwargs: 插件类型相关参数
                scanner: findings, client, recon_results
                recon: client
                analyzer: findings, recon_results
                report: findings, recon_results, output_dir

        Returns:
            扫描结果列表（Finding dict 或自定义数据）
        """
        raise NotImplementedError("插件必须实现 run() 方法")


class PluginLoader:
    """插件加载器 — 扫描目录、导入模块、实例化插件"""

    def __init__(self, extra_dirs: Optional[list[Path]] = None):
        self.logger = logging.getLogger(__name__)
        self.search_dirs = list(PLUGIN_DIRS)
        if extra_dirs:
            self.search_dirs.extend(extra_dirs)
        self._loaded: dict[str, VulnForgePlugin] = {}

    def discover(self) -> list[dict]:
        """扫描插件目录，返回发现的插件元数据列表"""
        discovered = []

        for plugin_dir in self.search_dirs:
            if not plugin_dir.exists():
                continue

            for f in plugin_dir.iterdir():
                if f.suffix == ".py" and not f.name.startswith("_"):
                    try:
                        plugin_cls = self._load_plugin_class(f)
                        if plugin_cls:
                            meta = {
                                "path": str(f),
                                "name": getattr(plugin_cls, "name", f.stem),
                                "description": getattr(plugin_cls, "description", ""),
                                "version": getattr(plugin_cls, "version", "1.0.0"),
                                "type": getattr(plugin_cls, "plugin_type", "scanner"),
                                "author": getattr(plugin_cls, "author", ""),
                            }
                            discovered.append(meta)
                    except Exception as e:
                        self.logger.debug("跳过非插件文件 %s: %s", f.name, e)

        return discovered

    def load_plugin(self, name: str) -> Optional[VulnForgePlugin]:
        """按名称加载插件（从缓存或重新加载）

        Args:
            name: 插件名（或文件名不含 .py）

        Returns:
            插件实例，失败返回 None
        """
        if name in self._loaded:
            return self._loaded[name]

        for plugin_dir in self.search_dirs:
            if not plugin_dir.exists():
                continue

            # 尝试直接文件名匹配
            plugin_file = plugin_dir / f"{name}.py"
            if plugin_file.exists():
                plugin = self._instantiate(plugin_file)
                if plugin:
                    self._loaded[name] = plugin
                    return plugin

            # 尝试扫描目录内的所有 .py 文件
            for f in plugin_dir.iterdir():
                if f.suffix == ".py" and f.stem != "__init__":
                    cls = self._load_plugin_class(f)
                    if cls and getattr(cls, "name", None) == name:
                        plugin = cls()
                        self._loaded[name] = plugin
                        return plugin

        self.logger.warning("插件未找到: %s", name)
        return None

    def load_all(self, plugin_type: str = "") -> list[VulnForgePlugin]:
        """加载所有插件（可按类型过滤）

        Args:
            plugin_type: 过滤类型（recon/scanner/analyzer/report），空字符串=全部

        Returns:
            已实例化的插件列表
        """
        plugins = []

        for plugin_dir in self.search_dirs:
            if not plugin_dir.exists():
                continue

            for f in plugin_dir.iterdir():
                if f.suffix == ".py" and not f.name.startswith("_"):
                    try:
                        cls = self._load_plugin_class(f)
                        if cls:
                            ptype = getattr(cls, "plugin_type", "")
                            if plugin_type and ptype != plugin_type:
                                continue
                            plugin = cls()
                            self._loaded[getattr(cls, "name", f.stem)] = plugin
                            plugins.append(plugin)
                    except Exception as e:
                        self.logger.debug("加载插件失败 %s: %s", f.name, e)

        return plugins

    def _load_plugin_class(self, file_path: Path):
        """从文件加载插件类"""
        spec = importlib.util.spec_from_file_location(file_path.stem, file_path)
        if not spec or not spec.loader:
            return None

        module = importlib.util.module_from_spec(spec)
        # 将模块加入 sys.modules 防止重复加载
        sys.modules[file_path.stem] = module
        spec.loader.exec_module(module)

        # 查找继承 VulnForgePlugin 的类
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, VulnForgePlugin)
                and obj is not VulnForgePlugin
                and hasattr(obj, "run")
                and obj.run is not VulnForgePlugin.run
            ):
                return obj

        return None

    def _instantiate(self, file_path: Path) -> Optional[VulnForgePlugin]:
        """从文件加载并实例化插件"""
        cls = self._load_plugin_class(file_path)
        if cls:
            try:
                return cls()
            except Exception as e:
                self.logger.error("实例化插件失败 %s: %s", file_path.name, e)
        return None

    def get_loaded(self) -> dict[str, VulnForgePlugin]:
        """返回已加载的插件字典"""
        return dict(self._loaded)


class PluginManager:
    """插件管理器 — install / uninstall / list 操作"""

    def __init__(self):
        self.loader = PluginLoader()
        self.logger = logging.getLogger(__name__)

    def list_plugins(self) -> list[dict]:
        """列出所有可用插件"""
        return self.loader.discover()

    def install(self, source_path: str, plugin_type: str = "scanner") -> bool:
        """从文件安装插件

        Args:
            source_path: 插件 Python 文件路径
            plugin_type: 插件类型（仅用于创建目录）

        Returns:
            是否安装成功
        """
        src = Path(source_path)
        if not src.exists():
            self.logger.error("插件文件不存在: %s", source_path)
            return False
        if src.suffix != ".py":
            self.logger.error("插件必须是 .py 文件")
            return False

        # 目标目录
        target_dir = Path.home() / ".vulnforge" / "plugins" / plugin_type
        target_dir.mkdir(parents=True, exist_ok=True)

        target_file = target_dir / src.name
        try:
            content = src.read_text(encoding="utf-8")
            target_file.write_text(content, encoding="utf-8")
            self.logger.info("插件已安装: %s → %s", src.name, target_file)
            return True
        except Exception as e:
            self.logger.error("插件安装失败: %s", e)
            return False

    def uninstall(self, plugin_name: str) -> bool:
        """卸载插件"""
        for plugin_dir in PLUGIN_DIRS:
            if not plugin_dir.exists():
                continue

            for f in plugin_dir.rglob(f"{plugin_name}.py"):
                try:
                    f.unlink()
                    self.logger.info("插件已卸载: %s", plugin_name)
                    # 清理空目录
                    parent = f.parent
                    if parent.exists() and not list(parent.iterdir()):
                        parent.rmdir()
                    return True
                except Exception as e:
                    self.logger.error("卸载失败: %s", e)
                    return False

        self.logger.warning("插件未找到: %s", plugin_name)
        return False
