# 每日只读日报自动化

日报规则、扫描边界和报告模板以本目录的 `SKILL.md` 与 `references/codex-storage-cleanup-sop.md` 为唯一来源。每日自动化只触发 Skill 的每日入口，并在当前自动化会话展示入口返回的 `chat_report`；提示文本不重复定义报告格式或候选策略。

首次手动调用 Skill 时，使用 Codex 自动化管理入口检查当前项目中是否已有每天北京时间 09:00 的存储检查任务。已有匹配任务就复用；只有提示过期时才更新，并保留其时间、项目、模型、推理强度、状态和本地运行设置。缺少任务时才创建，避免重复任务。自动化创建或更新必须通过 Codex 产品入口完成，不能直接改 `automation.toml`、launchd 或 crontab。

每日入口：

```sh
python3 /Users/mac/.codex/skills/codex-storage-cleanup/scripts/daily_codex_health.py --home "$HOME"
```

日报保持只读。失败或覆盖不完整时如实展示失败状态、已确认部分条目和缺口；不得将占位 `0` 当成没有候选，也不得在失败运行中创建或更新自动化。此文件不授权删除、移动、备份用户数据或操作 T1。
