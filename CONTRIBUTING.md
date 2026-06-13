# 贡献指南

感谢你考虑为 VulnForge 贡献代码！

## 开发环境

```bash
git clone https://github.com/yourname/vulnforge.git
cd vulnforge
pip install -e .
```

## 代码规范

- Python 3.10+
- 类型注解全程使用
- 日志使用 `logging.getLogger(__name__)` 而不是 `print`
- 异步 IO 使用 `asyncio` + `httpx`

## 提交 PR

1. Fork 本仓库
2. 创建特性分支: `git checkout -b feature/xxx`
3. 提交修改
4. 推送到分支
5. 创建 Pull Request

## 测试

```bash
pip install -e ".[dev]"
pytest tests/
```

## License

MIT
