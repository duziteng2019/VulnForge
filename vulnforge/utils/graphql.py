"""GraphQL 安全测试模块 — Introspection / DoS / 认证绕过 / Mutations 发现"""

import asyncio
import json
import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)

# 常见 GraphQL 端点
COMMON_GRAPHQL_ENDPOINTS = [
    "/graphql",
    "/graphiql",
    "/gql",
    "/api",
    "/api/graphql",
    "/v1/graphql",
    "/query",
]

# Introspection 查询
INTROSPECTION_QUERY = """query {
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}"""

# 简化的 Schema 查询（提取 mutations 和 queries）
SCHEMA_QUERY = """query {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}"""


class GraphQLTester:
    """GraphQL 安全测试器

    检测:
    - Introspection 是否开启（信息泄露）
    - 深度嵌套查询 DoS
    - 认证绕过
    - Mutations 发现
    """

    def __init__(self, config, target):
        self.config = config
        self.target = target
        self.endpoints = COMMON_GRAPHQL_ENDPOINTS
        self.findings: list[dict] = []
        self.logger = logging.getLogger(__name__)

    async def discover_endpoint(self, client) -> Optional[str]:
        """向常见 GraphQL 端点发送探测请求，返回第一个成功的端点 URL

        Args:
            client: httpx.AsyncClient 实例

        Returns:
            端点 URL 或 None
        """
        probe_query = '{"query": "query { __typename }"}'

        for ep in self.endpoints:
            url = self.target.resolve_path(ep)
            try:
                resp = await client.post(
                    url,
                    content=probe_query,
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                )
                if resp.status_code < 500:
                    try:
                        data = resp.json()
                        if isinstance(data, dict) and "data" in data:
                            self.logger.info(f"  [GraphQL] 发现端点: {url}")
                            return url
                    except (json.JSONDecodeError, TypeError):
                        continue
            except Exception as e:
                self.logger.debug(f"  [GraphQL] 端点探测失败 {url}: {e}")
                continue

        self.logger.debug("  [GraphQL] 未发现 GraphQL 端点")
        return None

    async def run(self, client) -> list[dict]:
        """执行全部 GraphQL 测试

        Args:
            client: httpx.AsyncClient 实例

        Returns:
            漏洞发现列表
        """
        endpoint = await self.discover_endpoint(client)
        if not endpoint:
            self.logger.info("  [GraphQL] 未找到端点，跳过测试")
            return []

        self.logger.info("  [GraphQL] 开始安全测试 — %s", endpoint)

        # 1. Introspection 测试
        intro_result = await self.test_introspection(client, endpoint)
        if intro_result:
            self.findings.append(intro_result)
            self.logger.info(
                "  [GraphQL] Introspection 开启: %s",
                intro_result.get("severity", ""),
            )

        # 2. 深度嵌套查询 DoS
        dos_result = await self.test_batch_depth(client, endpoint)
        if dos_result:
            self.findings.append(dos_result)
            self.logger.info("  [GraphQL] DoS 风险: %s", dos_result.get("severity", ""))

        # 3. 认证绕过测试
        auth_result = await self.test_auth_bypass(client, endpoint)
        if auth_result:
            self.findings.append(auth_result)
            self.logger.info(
                "  [GraphQL] 认证绕过: %s", auth_result.get("severity", "")
            )

        # 4. Mutations 发现（仅在 introspection 开启时）
        if intro_result:
            schema = await self.get_schema(client, endpoint)
            if schema:
                mutations = await self._extract_mutations(schema)
                if mutations:
                    self.findings.append(
                        {
                            "vuln_type": "graphql/mutations_discovered",
                            "url": endpoint,
                            "severity": "info",
                            "evidence": f"Mutations: {', '.join(mutations)}",
                            "description": f"发现 {len(mutations)} 个 GraphQL Mutation 操作: {', '.join(mutations)}",
                        }
                    )
                    self.logger.info(
                        "  [GraphQL] 发现 %d 个 Mutations", len(mutations)
                    )

        self.logger.info(
            "  [GraphQL] 测试完成，发现 %d 个问题", len(self.findings)
        )
        return self.findings

    async def test_introspection(
        self, client, endpoint: str
    ) -> Optional[dict]:
        """测试 Introspection 是否开启

        Args:
            client: httpx.AsyncClient 实例
            endpoint: GraphQL 端点 URL

        Returns:
            Finding dict 或 None
        """
        payload = json.dumps({"query": INTROSPECTION_QUERY})
        try:
            resp = await client.post(
                endpoint,
                content=payload,
                headers={"Content-Type": "application/json"},
                timeout=15,
            )

            if resp.status_code >= 500:
                return None

            try:
                data = resp.json()
            except (json.JSONDecodeError, TypeError):
                return None

            # 检查 introspection 是否开启
            if isinstance(data, dict):
                schema_data = data.get("data", {})
                if isinstance(schema_data, dict):
                    schema_info = schema_data.get("__schema", {})
                    if isinstance(schema_info, dict) and "types" in schema_info:
                        types = schema_info.get("types", [])
                        # 计算泄露的敏感信息量
                        type_count = len(types) if isinstance(types, list) else 0
                        return {
                            "vuln_type": "graphql/introspection_enabled",
                            "url": endpoint,
                            "severity": "high",
                            "evidence": f"Introspection 返回 {type_count} 个 types",
                            "description": f"GraphQL Introspection 已开启（严重信息泄露）— 攻击者可获取完整 Schema，了解所有 Query/Mutation/类型定义。返回 {type_count} 个类型。",
                        }

                    # 检查响应正文中是否包含 __schema 关键词
                    body_str = json.dumps(data)
                    if '"__schema"' in body_str or '"types"' in body_str:
                        return {
                            "vuln_type": "graphql/introspection_enabled",
                            "url": endpoint,
                            "severity": "high",
                            "evidence": "响应包含 __schema 或 types 字段",
                            "description": "GraphQL Introspection 已开启（严重信息泄露）— 攻击者可获取完整 Schema。",
                        }

        except Exception as e:
            self.logger.debug("  [GraphQL] Introspection 测试异常: %s", e)

        return None

    async def test_batch_depth(
        self, client, endpoint: str
    ) -> Optional[dict]:
        """测试深度嵌套查询 DoS

        发送深层嵌套的别名查询，对比响应时间与基线

        Args:
            client: httpx.AsyncClient 实例
            endpoint: GraphQL 端点 URL

        Returns:
            Finding dict 或 None
        """
        # 基线查询
        baseline_query = '{"query": "query { __typename }"}'
        # 深层嵌套查询 — 500 层别名
        deep_alias = " ".join([f"a{i}:__typename" for i in range(500)])
        deep_query = f'{{"query": "query {{ {deep_alias} }}"}}'

        try:
            # 基线请求
            t0 = time.time()
            resp_base = await client.post(
                endpoint,
                content=baseline_query,
                headers={"Content-Type": "application/json"},
                timeout=15,
            )
            baseline_time = time.time() - t0

            if resp_base.status_code >= 500:
                return None

            # 深度嵌套请求
            t0 = time.time()
            resp_deep = await client.post(
                endpoint,
                content=deep_query,
                headers={"Content-Type": "application/json"},
                timeout=30,
            )
            deep_time = time.time() - t0

            # 如果深度请求被拒绝（400+），可能服务端有限制
            if resp_deep.status_code >= 400:
                return {
                    "vuln_type": "graphql/query_depth_protected",
                    "url": endpoint,
                    "severity": "info",
                    "evidence": f"深度查询被拒绝: HTTP {resp_deep.status_code}",
                    "description": f"GraphQL 深度嵌套查询被服务端拒绝 (HTTP {resp_deep.status_code})，表明存在查询深度限制。",
                }

            # 判断 DoS 风险: 响应时间超过基线 5 倍
            if baseline_time > 0 and deep_time > baseline_time * 5:
                return {
                    "vuln_type": "graphql/dos_deep_nesting",
                    "url": endpoint,
                    "severity": "medium",
                    "evidence": f"基线: {baseline_time:.3f}s, 深度查询: {deep_time:.3f}s (x{deep_time / baseline_time:.1f})",
                    "description": f"GraphQL 深度嵌套查询可能导致 DoS — 响应时间从 {baseline_time:.3f}s 激增至 {deep_time:.3f}s (x{deep_time / baseline_time:.1f})，表明缺乏查询深度/复杂度限制。",
                }
            elif deep_time > 3 and deep_time > baseline_time * 3:
                # 虽然不到 5 倍，但仍然显著增加
                return {
                    "vuln_type": "graphql/dos_deep_nesting",
                    "url": endpoint,
                    "severity": "low",
                    "evidence": f"基线: {baseline_time:.3f}s, 深度查询: {deep_time:.3f}s (x{deep_time / baseline_time:.1f})",
                    "description": f"GraphQL 深度查询响应时间有所增加 — {baseline_time:.3f}s -> {deep_time:.3f}s。",
                }

        except Exception as e:
            self.logger.debug("  [GraphQL] 深度嵌套测试异常: %s", e)

        return None

    async def test_auth_bypass(
        self, client, endpoint: str
    ) -> Optional[dict]:
        """测试认证绕过 — 发送无认证头的请求，检查是否仍返回数据

        Args:
            client: httpx.AsyncClient 实例
            endpoint: GraphQL 端点 URL

        Returns:
            Finding dict 或 None
        """
        # 简单查询，不需要 introspection
        probe_query = '{"query": "query { __typename }"}'

        try:
            # 使用一个干净的 client（无认证头）发送请求
            # 克隆 client 并移除认证相关头
            import copy

            clean_headers = {
                k: v
                for k, v in client.headers.items()
                if k.lower()
                not in (
                    "authorization",
                    "cookie",
                    "x-api-key",
                    "token",
                    "x-auth-token",
                    "api-key",
                )
            }

            # 使用 client 的底层 transport 发送请求以避免共享 cookie
            from httpx import AsyncClient

            async with AsyncClient(
                timeout=client.timeout,
                verify=False,
                headers=clean_headers,
            ) as clean_client:
                resp = await clean_client.post(
                    endpoint,
                    content=probe_query,
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                )

                if resp.status_code >= 500:
                    return None

                try:
                    data = resp.json()
                except (json.JSONDecodeError, TypeError):
                    return None

                # 检查是否返回了数据（而不是认证错误）
                if isinstance(data, dict):
                    # 如果有 data 字段且包含数据，说明未经认证即可查询
                    response_data = data.get("data")
                    if response_data is not None and isinstance(
                        response_data, dict
                    ):
                        # 检查是否有认证错误消息
                        errors = data.get("errors", [])
                        auth_error_found = any(
                            isinstance(e, dict)
                            and any(
                                kw in str(e.get("message", "")).lower()
                                for kw in [
                                    "unauthorized",
                                    "unauthenticated",
                                    "forbidden",
                                    "not authenticated",
                                    "invalid token",
                                    "missing auth",
                                    "authorization",
                                    "access denied",
                                    "permission denied",
                                    "login required",
                                    "authentication required",
                                ]
                            )
                            for e in errors
                        )

                        if auth_error_found:
                            return {
                                "vuln_type": "graphql/auth_error_message",
                                "url": endpoint,
                                "severity": "info",
                                "evidence": f"认证错误消息: {errors[0].get('message', '') if errors else ''}",
                                "description": "GraphQL 端点有认证机制，但返回了详细的认证错误信息，可能泄露内部状态。",
                            }

                        # 如果成功返回数据且没有认证错误，则是认证绕过
                        if response_data.get("__typename") is not None:
                            return {
                                "vuln_type": "graphql/auth_bypass",
                                "url": endpoint,
                                "severity": "high",
                                "evidence": "无认证头请求成功返回数据",
                                "description": "GraphQL 端点无需认证即可查询 — 发送无认证头的请求成功返回了数据，存在认证绕过风险。",
                            }

        except Exception as e:
            self.logger.debug("  [GraphQL] 认证绕过测试异常: %s", e)

        return None

    async def get_schema(self, client, endpoint: str) -> Optional[dict]:
        """获取完整 GraphQL Schema（仅当 Introspection 开启时可用）

        Args:
            client: httpx.AsyncClient 实例
            endpoint: GraphQL 端点 URL

        Returns:
            Schema 字典，或 None
        """
        payload = json.dumps({"query": SCHEMA_QUERY})
        try:
            resp = await client.post(
                endpoint,
                content=payload,
                headers={"Content-Type": "application/json"},
                timeout=15,
            )

            if resp.status_code >= 500:
                return None

            try:
                data = resp.json()
            except (json.JSONDecodeError, TypeError):
                return None

            if isinstance(data, dict) and "data" in data:
                return data.get("data")

        except Exception as e:
            self.logger.debug("  [GraphQL] Schema 获取失败: %s", e)

        return None

    async def _extract_mutations(self, schema: dict) -> list[str]:
        """从 Schema 中提取所有 mutation 操作

        Args:
            schema: Schema 数据 (from get_schema)

        Returns:
            Mutation 名称列表
        """
        mutations = []

        if not isinstance(schema, dict):
            return mutations

        # 查找 mutation 类型
        mutation_type = schema.get("mutationType", {})
        mutation_type_name = (
            mutation_type.get("name") if isinstance(mutation_type, dict) else None
        )

        if not mutation_type_name:
            return mutations

        # 在所有 types 中查找 mutation 类型
        types = schema.get("types", [])
        if not isinstance(types, list):
            return mutations

        for t in types:
            if not isinstance(t, dict):
                continue
            if t.get("name") == mutation_type_name:
                fields = t.get("fields", [])
                if isinstance(fields, list):
                    for f in fields:
                        if isinstance(f, dict):
                            fname = f.get("name")
                            if fname:
                                mutations.append(fname)
                break

        return mutations
