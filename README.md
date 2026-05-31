# 🛡️ VulnForge — AI驱动自动化漏洞挖掘框架

> **输入目标URL，坐等漏洞报告。** 让AI成为你的渗透测试副驾。

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](CONTRIBUTING.md)

---

## 🤔 这是什么？

**VulnForge** 是一个将 **AI大模型** 与 **安全扫描工具** 深度融合的自动化漏洞挖掘框架。

传统自动挖洞工具的问题：扫描结果一大堆，真假难辨，还得人工分析。
VulnForge 的解法：让 AI 吃下所有扫描结果，自动去伪存真、评级排序、生成利用建议和修复方案。

**一句话：把安全专家的脑力装进自动化流水线。**

---

## ✨ 核心特性

| 特性 | 说明 |
| --- | --- |
| 🧠 **AI驱动分析** | 大模型自动理解漏洞上下文，判断真假，排除误报 |
| 🔄 **全链路自动化** | 信息收集 → 漏洞扫描 → Nuclei深度扫描 → AI分析 → 报告一键生成 |
| 🎯 **多维度检测** | SQL注入、XSS、SSRF、命令执行、敏感信息泄露、Nuclei 13,000+模板 |
| 🔌 **Nuclei引擎** | 集成社区最强POC引擎，13,000+现成模板，覆盖CVE/漏洞/配置/指纹 |
| 📊 **智能报告** | Markdown/HTML报告，含漏洞评级、POC、修复建议 |
| 🌐 **中文优先** | 全中文界面、中文报告、中文漏洞描述，国内白帽友好 |
| 🔌 **可扩展** | 插件式架构，轻松接入自定义POC、扫描器、AI模型 |

---

## 🚀 快速开始

```bash
# 1. 安装
pip install vulnforge

# 2. 配置API Key（暂支持DeepSeek/OpenAI/GLM）
vulnforge config set api_key sk-your-key
vulnforge config set ai_provider deepseek

# 3. 一键挖洞
vulnforge scan https://example.com
```

---

## 📦 安装

### 前置条件

- Python 3.10+
- 安全工具（可选，自动检测）：nmap, nuclei, subfinder, httpx

```bash
# 推荐方式
pip install vulnforge

# 或者从源码安装
git clone https://github.com/yourname/vulnforge.git
cd vulnforge
pip install -e .
```

---

## 🎮 使用指南

### 基础扫描

```bash
# 对单个目标进行全链路扫描
vulnforge scan https://target.com
```

### 批量扫描

```bash
# 从文件读取目标列表
vulnforge scan targets.txt

# 逗号分隔
vulnforge scan https://site1.com,https://site2.com

# 指定并发数
vulnforge scan targets.txt --concurrent 5
```

### 扫描模式

```bash

### 配置AI模型

```bash
# DeepSeek（推荐，性价比高）
vulnforge config set ai_provider deepseek
vulnforge config set api_key sk-xxxxx

# OpenAI
vulnforge config set ai_provider openai
vulnforge config set api_key sk-xxxxx

# 智谱GLM
vulnforge config set ai_provider glm
vulnforge config set api_key xxxxx
```

### 查看结果

```bash
# 列出历史扫描
vulnforge list

# 查看某次扫描详情
vulnforge show <scan_id>
```

---

## 🚀 快速演示

```bash
# 一键扫描（含AI分析需配置API Key）
$ vulnforge scan https://httpbin.org/get?id=1 --mode scan-only

🛡️  VulnForge v0.2.0
🎯  Target: https://httpbin.org/get?id=1
⚙️   Mode: scan-only

[→] 阶段: scanner
  [→] Nuclei扫描中 (13,000+ 模板)...
  [✓] Nuclei发现 0 个漏洞
  [✓] 发现漏洞: 22 个
       high: 1
       medium: 21

[✓] 扫描完成 | 耗时: 12.4s

📊 扫描总结
==================================================
  漏洞总数: 22
    high: 1
    medium: 21
  扫描耗时: 12.4s
```

```bash
# 批量扫描
$ vulnforge scan targets.txt --concurrent 3
🛡️  VulnForge v0.2.0 — 批量扫描模式
🎯  共 10 个目标
⚙️   并发: 3

[1/10] 🔍 https://target1.com
[2/10] 🔍 https://target2.com
[3/10] 🔍 https://target3.com
...

📊 批量扫描完成
  总计: 10 目标, 47 漏洞
```

---

## 🏗️ 架构

```
┌─────────────────────────────────────────────────────┐
│                    vulnforge CLI                      │
├─────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
│  │   Recon   │  │  Scanner │  │    AI     │           │
│  │ 信息收集  │→ │ 漏洞扫描  │→ │ 智能分析  │           │
│  │          │  │          │  │          │           │
│  │• 子域名  │  │• SQL注入  │  │• 误报过滤 │           │
│  │• 端口扫描│  │• XSS     │  │• 漏洞评级 │           │
│  │• 指纹识别│  │• SSRF    │  │• POC生成  │           │
│  │• 爬虫   │  │• 命令注入 │  │• 修复建议 │           │
│  │• 敏感信息│  │• 目录扫描 │  │• 报告生成 │           │
│  └──────────┘  └──────────┘  └──────────┘           │
├─────────────────────────────────────────────────────┤
│  🔌 Plugin System │ 📊 Reporter │ ⚙️ Config Engine   │
└─────────────────────────────────────────────────────┘
```

---

## 🧪 扫描能力矩阵

| 漏洞类型 | 检测方式 | AI验证 | POC生成 |
| --- | --- | --- | --- |
| SQL注入 | 布尔盲注+时间盲注+报错注入 | ✅ | ✅ |
| XSS(反射型/存储型/DOM型) | 多向量Payload测试 | ✅ | ✅ |
| SSRF | URL参数遍历+回调检测 | ✅ | ✅ |
| 命令注入 | 系统命令注入测试 | ✅ | ✅ |
| 敏感信息泄露 | 正则匹配+路径探测 | ✅ | — |
| 目录遍历 | 路径穿越测试 | ✅ | ✅ |
| 开放重定向 | URL跳转检测 | ✅ | — |
| CORS配置错误 | Origin反射测试 | ✅ | — |
| 信息泄露（指纹） | 服务版本识别+CVE匹配 | ✅ | — |

---

## 🤝 贡献指南

欢迎各种形式的贡献！提交 Issue、PR 或加入讨论。

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing`)
3. 提交修改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing`)
5. 创建 Pull Request

---

## 📄 License

MIT License — 随便用，随便改，随便玩。

---

## ⭐ Star History

**如果你觉得这个项目有用，请给个 Star ⭐，支持国产安全工具发展！**
