"""User-Agent 轮换 + 自适应并发控制"""

import asyncio
import logging
import random
import time
from typing import Optional

logger = logging.getLogger(__name__)

# 常见 User-Agent 池（覆盖主流浏览器和爬虫）
USER_AGENTS: list[str] = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    # Chrome macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    # Edge Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    # Firefox macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.6; rv:133.0) Gecko/20100101 Firefox/133.0",
    # Safari macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    # Mobile Chrome
    "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.200 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S926B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.200 Mobile Safari/537.36",
    # Mobile Safari (iOS)
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
]


def random_user_agent() -> str:
    """从 User-Agent 池中随机选择一个"""
    return random.choice(USER_AGENTS)


class AdaptiveRateLimiter:
    """自适应速率限制器

    根据目标响应时间动态调整请求速率。
    如果响应变慢，自动降低并发和增加间隔。
    """

    def __init__(
        self,
        initial_concurrency: int = 5,
        min_concurrency: int = 1,
        max_concurrency: int = 20,
        base_delay: float = 0.0,
        max_delay: float = 3.0,
        jitter: float = 0.5,
    ):
        self.current_concurrency = initial_concurrency
        self.min_concurrency = min_concurrency
        self.max_concurrency = max_concurrency
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.jitter = jitter

        # 响应时间追踪
        self.response_times: list[float] = []
        self.window_size = 10
        self.last_adjust_time = time.time()
        self.adjust_interval = 5.0  # 每 5 秒调整一次

        self.logger = logging.getLogger(__name__)

    def record_response_time(self, elapsed: float) -> None:
        """记录一次请求响应时间"""
        self.response_times.append(elapsed)
        if len(self.response_times) > self.window_size:
            self.response_times.pop(0)

        # 定期调整
        now = time.time()
        if now - self.last_adjust_time >= self.adjust_interval:
            self._adjust()
            self.last_adjust_time = now

    def _adjust(self) -> None:
        """根据响应时间动态调整并发和延迟"""
        if len(self.response_times) < 3:
            return

        avg_time = sum(self.response_times) / len(self.response_times)
        baseline = sorted(self.response_times)[len(self.response_times) // 2]  # 中位数

        if avg_time > 5.0 and baseline > 3.0:
            # 响应很慢，降低并发
            self.current_concurrency = max(
                self.min_concurrency,
                self.current_concurrency - 1,
            )
            self.base_delay = min(self.max_delay, self.base_delay + 0.2)
            self.logger.debug(
                "降速: avg=%.2fs, concurrency=%d, delay=%.1fs",
                avg_time, self.current_concurrency, self.base_delay,
            )
        elif avg_time < 1.0 and baseline < 0.5:
            # 响应很快，适当提升并发
            self.current_concurrency = min(
                self.max_concurrency,
                self.current_concurrency + 1,
            )
            self.base_delay = max(0.0, self.base_delay - 0.1)
            self.logger.debug(
                "加速: avg=%.2fs, concurrency=%d, delay=%.1fs",
                avg_time, self.current_concurrency, self.base_delay,
            )

    def get_delay(self) -> float:
        """返回本次请求前应当等待的秒数（含 jitter）"""
        delay = self.base_delay + random.uniform(0, self.jitter)
        return delay

    async def wait_if_needed(self) -> None:
        """如果需要，等待一段时间再发送下一个请求"""
        delay = self.get_delay()
        if delay > 0:
            await asyncio.sleep(delay)

    @property
    def concurrency(self) -> int:
        return self.current_concurrency

    def get_headers(self) -> dict[str, str]:
        """生成带随机 User-Agent 的请求头"""
        return {
            "User-Agent": random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
        }
