# 现存自动化兼容说明

本机已有一个每日 Codex 存储清理自动化，配置位于 `/Users/mac/.codex/automations/codex/automation.toml`。它仍从旧入口读取 Skill 说明和参考文件，并调用：

```sh
python3 /Users/mac/.codex/skills/storage-observatory/subskills/codex-storage-cleanup/scripts/apply_cleanup.py --home /Users/mac --apply
```

本次拆分不修改自动化配置、频率或动作。旧目录作为兼容别名指向 `/Users/mac/.codex/skills/codex-storage-cleanup`，因此现有命令仍可读取独立包中的 `SKILL.md`、`references/` 和 `scripts/`。手动维护和调用请使用独立 Skill 根目录。

独立日报入口是 `scripts/daily_codex_health.py`，默认只读，结果写入 `$HOME/.codex/skill-workspaces/codex-storage-cleanup/daily`。日报入口与上述现存清理自动化是两条不同路径。
