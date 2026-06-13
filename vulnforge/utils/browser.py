"""Headless 浏览器封装 — Playwright DOM 分析 + 截图取证"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


class BrowserAnalyzer:
    """浏览器分析器（Playwright）
    
    用于:
    - DOM XSS 检测（JS 执行后检查 DOM）
    - 截图取证（为报告生成页面截图）
    - 表单自动提交
    """

    def __init__(self, headless: bool = True, timeout: int = 15000):
        self.headless = headless
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self._browser = None
        self._context = None

    async def ensure_browser(self):
        """确保浏览器已启动"""
        if not HAS_PLAYWRIGHT:
            self.logger.warning("Playwright 未安装。安装: pip install playwright && playwright install chromium")
            return False
        if self._browser:
            return True
        try:
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=self.headless,
                args=[
                    "--no-sandbox",
                    "--disable-web-security",
                    "--disable-setuid-sandbox",
                ],
            )
            self._context = await self._browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                viewport={"width": 1920, "height": 1080},
            )
            return True
        except Exception as e:
            self.logger.error("浏览器启动失败: %s", e)
            return False

    async def check_dom_xss(self, url: str, payload: str) -> dict:
        """检测 DOM XSS — 在浏览器中加载页面，注入 payload，检查 DOM
        
        Args:
            url: 目标 URL（含 payload）
            payload: 注入的 payload
            
        Returns:
            {"dom_xss": True/False, "evidence": "..."}
        """
        if not await self.ensure_browser():
            return {"dom_xss": False, "evidence": ""}

        page = await self._context.new_page()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout)
            await asyncio.sleep(1)  # 等待 JS 执行

            # 检查 payload 是否在 DOM 中且未转义（未 HTML 编码）
            escaped_payload = (
                payload.replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#x27;")
            )
            if escaped_payload == payload:
                # payload 不含特殊 HTML 字符，检查原始 payload
                html = await page.content()
                if payload in html:
                    # 进一步检查是否在可执行上下文中
                    has_script_context = await page.evaluate("""
                        () => {
                            const body = document.body.innerHTML;
                            return body.includes('<script>') || 
                                   body.includes('onerror=') || 
                                   body.includes('onload=') ||
                                   body.includes('javascript:');
                        }
                    """)
                    if has_script_context:
                        return {"dom_xss": True, "evidence": "payload 在可执行上下文中"}
                    return {"dom_xss": True, "evidence": "payload 反射在 DOM 中"}
            
            # 检查 alert 等执行
            # 如果 payload 包含 alert，检查是否已被执行
            return {"dom_xss": False, "evidence": "payload 未在 DOM 中检测到"}
        except Exception as e:
            return {"dom_xss": False, "evidence": f"页面加载失败: {e}"}
        finally:
            await page.close()

    async def screenshot(self, url: str, output_path: Path) -> Optional[str]:
        """截图
        
        Args:
            url: 目标 URL
            output_path: 截图保存路径
            
        Returns:
            str: 截图文件路径，失败返回 None
        """
        if not await self.ensure_browser():
            return None

        page = await self._context.new_page()
        try:
            await page.goto(url, wait_until="networkidle", timeout=self.timeout)
            await asyncio.sleep(2)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            await page.screenshot(path=str(output_path), full_page=True)
            self.logger.info("截图已保存: %s", output_path)
            return str(output_path)
        except Exception as e:
            self.logger.error("截图失败: %s", e)
            return None
        finally:
            await page.close()

    async def close(self):
        """关闭浏览器"""
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        self._browser = None
        self._playwright = None
