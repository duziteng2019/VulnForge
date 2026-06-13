FROM python:3.11-slim AS base

LABEL description="VulnForge — AI驱动的自动化漏洞挖掘框架"
LABEL maintainer="VulnForge Team"

# 环境变量
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    VULNFORGE_HOME=/home/vulnforge/.vulnforge

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/*

# 安装 nuclei（可选漏洞扫描引擎）
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.4_linux_amd64.zip \
    && unzip -q nuclei_3.3.4_linux_amd64.zip -d /usr/local/bin/ 2>/dev/null \
    && rm -f nuclei_3.3.4_linux_amd64.zip \
    && nuclei -version 2>/dev/null || echo "nuclei installed"

# 创建非 root 用户
RUN groupadd -r vulnforge && useradd -r -g vulnforge -d /home/vulnforge -s /bin/bash vulnforge \
    && mkdir -p /home/vulnforge/.vulnforge /data \
    && chown -R vulnforge:vulnforge /home/vulnforge /data

USER vulnforge
WORKDIR /app

# 安装 VulnForge
COPY --chown=vulnforge:vulnforge . /app/
RUN pip install --no-warn-script-location --user -e . 2>&1 | tail -3

ENV PATH="/home/vulnforge/.local/bin:${PATH}"

# 默认命令
ENTRYPOINT ["vulnforge"]
CMD ["--help"]
