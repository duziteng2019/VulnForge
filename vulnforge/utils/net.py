"""网络工具函数"""

import httpx


async def check_url_alive(url: str, timeout: int = 10) -> bool:
    """检查URL是否存活"""
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            resp = await client.head(url, follow_redirects=True, timeout=timeout)
            return resp.status_code < 500
    except Exception:
        return False


async def fetch_page(url: str, timeout: int = 15) -> str:
    """获取页面内容"""
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            resp = await client.get(url, follow_redirects=True, timeout=timeout)
            return resp.text
    except Exception as e:
        raise ConnectionError(f"获取页面失败: {e}")
