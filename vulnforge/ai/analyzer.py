"""AI分析模块 — 漏洞分析 / POC生成 / 智能报告"""

import asyncio
import json
import os
from pathlib import Path
from typing import Optional

import httpx

from ..core.config import VulnForgeConfig
from ..core.target import Target


class AIAnalyzer:
    """AI漏洞分析器"""

    def __init__(self, config: VulnForgeConfig, target: Target):
        self.config = config
        self.target = target
        self.provider = config.get("ai_provider", "deepseek")
        self.api_key = config.get("api_key", "")
        self.api_base = config.get("api_base", "")
        self.model = config.get("model", "deepseek-chat")
        self.temperature = config.get("ai.temperature", 0.3)
        self.max_tokens = config.get("ai.max_tokens", 4096)

    def _get_api_config(self) -> dict:
        """获取API配置"""
        configs = {
            "deepseek": {
                "api_base": "https://api.deepseek.com",
                "model": "deepseek-chat",
                "auth_header": "Authorization",
                "auth_prefix": "Bearer ",
            },
            "openai": {
                "api_base": "https://api.openai.com",
                "model": "gpt-4o-mini",
                "auth_header": "Authorization",
                "auth_prefix": "Bearer ",
            },
            "glm": {
                "api_base": "https://open.bigmodel.cn/api/paas/v4",
                "model": "glm-4-flash",
                "auth_header": "Authorization",
                "auth_prefix": "Bearer ",
            },
        }

        base = configs.get(self.provider, configs["deepseek"])

        if self.api_base:
            base["api_base"] = self.api_base
        if self.model != "deepseek-chat":
            base["model"] = self.model

        return base

    async def run(self, output_dir: Path, scan_results: dict) -> dict:
        """执行AI分析"""
        results = {
            "analysis": [],
            "poc": [],
            "report": "",
            "status": "completed",
        }

        findings = scan_results.get("scanner", {}).get("findings", [])
        recon_info = scan_results.get("recon", {})

        if not findings:
            self.logger.info("无漏洞发现，跳过AI分析")
            results["status"] = "skipped"
            return results

        if not self.api_key:
            self.logger.warning("未配置API Key，使用本地规则分析")
            results["analysis"] = self._local_analysis(findings)
            return results

        try:
            # 1. AI漏洞分析
            self.logger.info("AI分析漏洞详情...")
            analysis = await self._ai_analyze_findings(findings, recon_info)
            results["analysis"] = analysis

            # 2. AI POC生成
            if self.config.get("ai.enable_poc_generation", True):
                self.logger.info("AI生成POC...")
                poc = await self._ai_generate_poc(findings)
                results["poc"] = poc

            # 3. AI报告生成
            if self.config.get("ai.enable_report", True):
                self.logger.info("AI生成报告...")
                report = await self._ai_generate_report(findings, analysis, recon_info)
                results["report"] = report

                # 保存报告
                report_path = output_dir / "report.md"
                with open(report_path, "w", encoding="utf-8") as f:
                    f.write(report)

        except Exception as e:
            self.logger.error(f"AI分析出错: {e}")
            results["status"] = "error"
            results["error"] = str(e)
            # Fallback到本地分析
            results["analysis"] = self._local_analysis(findings)

        # 保存AI结果
        with open(output_dir / "ai_analysis.json", "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2, default=str)

        return results

    def _local_analysis(self, findings: list) -> list:
        """本地规则分析（无API时的fallback）"""
        analysis = []
        for f in findings:
            vuln_type = f.get("vuln_type", "unknown")
            param = f.get("param", "")
            evidence = f.get("evidence", "")

            description = self._get_vuln_description(vuln_type, param)
            risk = self._assess_risk(f)
            suggestion = self._get_suggestion(vuln_type)

            analysis.append({
                "vuln_type": vuln_type,
                "url": f.get("url", ""),
                "param": param,
                "description": description,
                "risk_assessment": risk,
                "fix_suggestion": suggestion,
                "verified": True,
            })

        return analysis

    async def _ai_analyze_findings(self, findings: list, recon_info: dict) -> list:
        """使用AI分析漏洞详情"""
        api = self._get_api_config()

        # 构造分析提示
        prompt = self._build_analysis_prompt(findings, recon_info)

        headers = {
            "Content-Type": "application/json",
            api["auth_header"]: f"{api['auth_prefix']}{self.api_key}",
        }

        data = {
            "model": api["model"],
            "messages": [
                {
                    "role": "system",
                    "content": "你是一个专业的网络安全渗透测试专家。请对以下扫描结果进行深度分析，"
                               "判断真伪漏洞，排除误报，给出风险评级和修复建议。"
                               "直接输出JSON数组，不要额外说明。"
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }

        async with httpx.AsyncClient(timeout=120) as client:
            try:
                resp = await client.post(
                    f"{api['api_base']}/v1/chat/completions",
                    headers=headers,
                    json=data,
                    timeout=120,
                )
                if resp.status_code == 200:
                    content = resp.json()["choices"][0]["message"]["content"]
                    # 尝试提取JSON
                    return self._extract_json_array(content, findings)
                else:
                    self.logger.error(f"API返回异常: {resp.status_code}")
                    return self._local_analysis(findings)
            except Exception as e:
                self.logger.error(f"API调用失败: {e}")
                return self._local_analysis(findings)

    async def _ai_generate_poc(self, findings: list) -> list:
        """使用AI生成漏洞验证POC"""
        api = self._get_api_config()

        # 只对高危以上生成POC
        critical_findings = [
            f for f in findings
            if f.get("severity") in ("critical", "high")
        ][:3]  # 最多3个

        if not critical_findings:
            return []

        poc_list = []
        for finding in critical_findings:
            headers = {
                "Content-Type": "application/json",
                api["auth_header"]: f"{api['auth_prefix']}{self.api_key}",
            }

            prompt = (
                f"你是一个安全渗透测试专家。请为以下漏洞生成一个可用的Python验证POC脚本。\n\n"
                f"漏洞类型: {finding.get('vuln_type')}\n"
                f"目标URL: {finding.get('url')}\n"
                f"参数: {finding.get('param')}\n"
                f"Payload: {finding.get('payload')}\n"
                f"描述: {finding.get('description')}\n\n"
                f"要求:\n"
                f"1. 使用requests库，完整可运行\n"
                f"2. 包含详细的注释\n"
                f"3. 只输出代码，不要多余说明\n"
                f"4. 安全可控，不对目标造成破坏性影响"
            )

            data = {
                "model": api["model"],
                "messages": [
                    {"role": "system", "content": "你是一个安全专家。生成Python POC代码。"},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.2,
                "max_tokens": 2048,
            }

            try:
                async with httpx.AsyncClient(timeout=60) as client:
                    resp = await client.post(
                        f"{api['api_base']}/v1/chat/completions",
                        headers=headers,
                        json=data,
                        timeout=60,
                    )
                    if resp.status_code == 200:
                        code = resp.json()["choices"][0]["message"]["content"]
                        poc_list.append({
                            "vuln_type": finding.get("vuln_type"),
                            "url": finding.get("url"),
                            "poc_code": code,
                        })
            except Exception:
                continue

        return poc_list

    async def _ai_generate_report(self, findings: list, analysis: list, recon_info: dict) -> str:
        """使用AI生成完整的安全报告"""
        api = self._get_api_config()

        tech_str = ", ".join(recon_info.get("technologies", [])) or "未知"
        ip = recon_info.get("ip", "未知")

        prompt = (
            f"你是一个安全报告撰写专家。请根据以下扫描结果生成一份专业的中文安全审计报告。\n\n"
            f"目标信息:\n"
            f"- URL: {self.target.url}\n"
            f"- 域名: {self.target.domain}\n"
            f"- IP: {ip}\n"
            f"- 技术栈: {tech_str}\n\n"
            f"漏洞发现 ({len(findings)}个):\n"
            f"{json.dumps(findings, ensure_ascii=False, indent=2)}\n\n"
            f"AI分析结果:\n"
            f"{json.dumps(analysis, ensure_ascii=False, indent=2)}\n\n"
            f"请生成包含以下章节的完整报告:\n"
            f"1. 概述 - 扫描目标、时间、范围\n"
            f"2. 漏洞统计 - 按严重级别汇总\n"
            f"3. 高危漏洞详情 - 逐个描述、风险、修复方案\n"
            f"4. 中低危漏洞详情\n"
            f"5. 安全建议 - 综合加固建议\n"
            f"6. 附录 - 扫描配置\n\n"
            f"格式: Markdown，专业正式，中文"
        )

        headers = {
            "Content-Type": "application/json",
            api["auth_header"]: f"{api['auth_prefix']}{self.api_key}",
        }

        data = {
            "model": api["model"],
            "messages": [
                {"role": "system", "content": "你是一个专业的安全审计报告撰写专家。"},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.3,
            "max_tokens": 8192,
        }

        try:
            async with httpx.AsyncClient(timeout=180) as client:
                resp = await client.post(
                    f"{api['api_base']}/v1/chat/completions",
                    headers=headers,
                    json=data,
                    timeout=180,
                )
                if resp.status_code == 200:
                    return resp.json()["choices"][0]["message"]["content"]
        except Exception:
            pass

        # Fallback: 本地生成报告
        return self._local_report(findings, recon_info)

    def _build_analysis_prompt(self, findings: list, recon_info: dict) -> str:
        """构建分析提示词"""
        tech_str = ", ".join(recon_info.get("technologies", [])) or "未知"
        return (
            f"分析以下安全扫描结果，输出JSON数组格式。每个元素包含:\n"
            f"- vuln_type: 漏洞类型\n"
            f"- url: 目标URL\n"
            f"- param: 参数名\n"
            f"- description: 漏洞描述（中文）\n"
            f"- risk_assessment: 风险评估（中文，含利用难度、影响范围）\n"
            f"- fix_suggestion: 修复建议（中文，具体可操作）\n"
            f"- verified: true/false（是否为真漏洞）\n\n"
            f"目标技术栈: {tech_str}\n"
            f"目标URL: {self.target.url}\n\n"
            f"扫描结果:\n{json.dumps(findings, ensure_ascii=False, indent=2)}"
        )

    def _extract_json_array(self, content: str, fallback_findings: list) -> list:
        """从AI响应中提取JSON数组"""
        import re as _re
        # 尝试找```json ... ```
        match = _re.search(r"```(?:json)?\s*(\[[\s\S]*?\])\s*```", content)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        # 尝试直接解析
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass

        # 尝试找第一个[到最后一个]
        start = content.find("[")
        end = content.rfind("]")
        if start != -1 and end != -1:
            try:
                return json.loads(content[start:end + 1])
            except json.JSONDecodeError:
                pass

        return self._local_analysis(fallback_findings)

    def _get_vuln_description(self, vuln_type: str, param: str) -> str:
        """获取漏洞描述"""
        descriptions = {
            "sql_injection": f"参数 '{param}' 存在SQL注入漏洞，攻击者可利用该漏洞获取数据库敏感信息、执行任意SQL语句。",
            "sql_injection_time_blind": f"参数 '{param}' 存在基于时间的SQL盲注，攻击者可逐字符猜解数据库内容。",
            "xss_reflected": f"参数 '{param}' 存在反射型跨站脚本(XSS)漏洞，攻击者可注入恶意脚本窃取用户信息。",
            "ssrf": f"参数 '{param}' 存在服务器端请求伪造(SSRF)漏洞，攻击者可探测内网服务。",
            "command_injection": f"参数 '{param}' 存在命令注入漏洞，攻击者可远程执行系统命令。",
            "exposed_path": "敏感路径/文件暴露，可能泄露系统配置或敏感信息。",
        }
        return descriptions.get(vuln_type, f"发现安全漏洞: {vuln_type}")

    def _assess_risk(self, finding: dict) -> str:
        """评估风险"""
        severity = finding.get("severity", "medium")
        vuln_type = finding.get("vuln_type", "")

        risks = {
            "critical": "严重风险 — 可直接获取服务器控制权或核心数据，需立即修复",
            "high": "高危风险 — 可能导致敏感信息泄露或权限提升，应尽快修复",
            "medium": "中危风险 — 可能配合其他漏洞利用，建议在迭代中修复",
            "low": "低危风险 — 信息泄露类问题，建议择机修复",
            "info": "信息 — 仅作参考，无直接安全威胁",
        }
        return risks.get(severity, risks["medium"])

    def _get_suggestion(self, vuln_type: str) -> str:
        """获取修复建议"""
        suggestions = {
            "sql_injection": "1. 使用参数化查询/预编译语句\n2. 对用户输入进行严格过滤和转义\n3. 使用ORM框架\n4. 最小化数据库账户权限",
            "xss_reflected": "1. 对输出进行HTML实体编码\n2. 设置Content-Security-Policy头\n3. 对用户输入进行白名单验证",
            "ssrf": "1. 限制请求的目标IP范围（禁止内网地址）\n2. 对URL进行白名单验证\n3. 禁用不必要的协议（file://, dict://, gopher://）",
            "command_injection": "1. 避免直接拼接系统命令\n2. 使用安全的API替代shell命令\n3. 对输入进行严格的格式验证",
            "exposed_path": "1. 移除不必要的敏感文件\n2. 配置访问控制\n3. 使用Web应用防火墙屏蔽敏感路径",
        }
        return suggestions.get(vuln_type, "建议对相关输入进行严格的安全过滤和验证。")

    def _local_report(self, findings: list, recon_info: dict) -> str:
        """本地生成报告"""
        tech_str = ", ".join(recon_info.get("technologies", [])) or "未知"
        ip = recon_info.get("ip", "未知")

        lines = []
        lines.append(f"# 安全审计报告\n")
        lines.append(f"## 1. 概述")
        lines.append(f"- **目标**: {self.target.url}")
        lines.append(f"- **域名**: {self.target.domain}")
        lines.append(f"- **IP**: {ip}")
        lines.append(f"- **技术栈**: {tech_str}")
        lines.append(f"- **扫描时间**: {__import__('datetime').datetime.now().isoformat()}")
        lines.append("")

        # 漏洞统计
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "medium")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lines.append("## 2. 漏洞统计")
        lines.append(f"| 严重级别 | 数量 |")
        lines.append(f"| --- | --- |")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in severity_counts:
                labels = {"critical": "🔴 严重", "high": "🟠 高危", "medium": "🟡 中危", "low": "🟢 低危", "info": "ℹ️ 信息"}
                lines.append(f"| {labels.get(sev, sev)} | {severity_counts[sev]} |")
        lines.append(f"| **合计** | **{len(findings)}** |")
        lines.append("")

        # 漏洞详情
        lines.append("## 3. 漏洞详情")
        for i, f in enumerate(findings, 1):
            severity = f.get("severity", "medium")
            sev_label = {"critical": "🔴 严重", "high": "🟠 高危", "medium": "🟡 中危", "low": "🟢 低危", "info": "ℹ️ 信息"}.get(severity, severity)
            lines.append(f"### {i}. [{sev_label}] {f.get('vuln_type')}")
            lines.append(f"- **URL**: {f.get('url', 'N/A')}")
            if f.get("param"):
                lines.append(f"- **参数**: {f['param']}")
            if f.get("payload"):
                lines.append(f"- **Payload**: `{f['payload']}`")
            lines.append(f"- **证据**: {f.get('evidence', 'N/A')}")
            lines.append(f"- **描述**: {self._get_vuln_description(f.get('vuln_type', ''), f.get('param', ''))}")
            lines.append(f"- **风险评估**: {self._assess_risk(f)}")
            lines.append(f"- **修复建议**: {self._get_suggestion(f.get('vuln_type', ''))}")
            lines.append("")

        lines.append("## 4. 安全建议")
        lines.append("1. 对所有用户输入进行严格的验证和过滤")
        lines.append("2. 使用Web应用防火墙(WAF)")
        lines.append("3. 定期进行安全扫描和渗透测试")
        lines.append("4. 及时更新和修补已知漏洞")
        lines.append("5. 遵循安全编码规范")
        lines.append("")

        lines.append("---")
        lines.append(f"*报告由 VulnForge AI 自动生成 | {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')}*")

        return "\n".join(lines)
