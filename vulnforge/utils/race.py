"""Race Condition (竞争条件) 检测模块

检测场景:
1. 优惠券/折扣 — 同时发送多个请求兑换同一个优惠码
2. 余额/积分 — 同时发送多个请求增加积分
3. 库存 — 同时发送多个请求下单（同一商品）
4. 点赞/投票 — 同时发送多个请求投票

检测方法:
1. 从 recon 的 endpoints 和 forms 中找出 POST 端点
2. 对每个端点发送 N 个并发请求（N=5）
3. 检查响应中是否有多个 200/201（说明被处理了多次）
4. 正常情况应该有些请求返回 4xx/5xx（被竞争机制拦截）
"""

import asyncio
import logging

logger = logging.getLogger(__name__)


class RaceConditionTester:
    """Race Condition 检测器"""

    def __init__(self, config, target):
        self.config = config
        self.target = target
        self.findings: list[dict] = []

    async def run(self, client, endpoints: list[dict]) -> list[dict]:
        """执行 Race Condition 测试

        Args:
            client: 共享 httpx client
            endpoints: [{"url": "...", "method": "POST", "data": {...}}, ...]

        Returns:
            发现的漏洞列表
        """
        self.findings = []
        if not endpoints:
            logger.debug("  [Race] 无端点数据，跳过 Race Condition 检测")
            return []

        logger.info(f"  [Race] 开始 Race Condition 检测，共 {len(endpoints)} 个端点")

        for ep in endpoints:
            try:
                finding = await self._test_endpoint(client, ep)
                if finding:
                    self.findings.append(finding)
            except Exception as e:
                logger.debug(f"  [Race] 端点测试异常: {ep.get('url', '')} - {e}")

        if self.findings:
            logger.info(f"  [Race] 发现 {len(self.findings)} 个可能的 Race Condition 漏洞")
        else:
            logger.info("  [Race] 未发现 Race Condition 漏洞")

        return self.findings

    async def _test_endpoint(self, client, ep):
        """对一个端点发送 5 并发请求

        Args:
            client: httpx.AsyncClient
            ep: {"url": "...", "method": "POST", "data": {...}}

        Returns:
            如果检测到 Race Condition 则返回 finding dict，否则返回 None
        """
        url = ep.get("url", "")
        if not url:
            return None

        async def send_one():
            try:
                if ep.get("method", "POST").upper() == "POST":
                    resp = await client.post(url, data=ep.get("data", {}))
                else:
                    resp = await client.get(url)
                return resp.status_code
            except Exception:
                return 0

        # 发送 5 个并发请求
        responses = await asyncio.gather(*[send_one() for _ in range(5)])
        success_count = sum(1 for s in responses if s == 200 or s == 201)

        if success_count >= 3:
            # 5个请求中3个以上成功 = 可能存在 Race Condition
            return {
                "vuln_type": "race_condition",
                "url": url,
                "severity": "high",
                "evidence": f"5并发请求中{success_count}个成功",
                "description": "并发请求未正确加锁，可能存在竞态条件",
            }

        return None
