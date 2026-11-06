# Codex 存储清理（codex-storage-cleanup）

这是可以单独复制和安装的 Codex 存储检查与默认清理 Skill。它只遍历系统账号资料确认的当前账号内、带有 Codex 来源证据的本地根目录；不遍历整个 home、其他账号、iCloud 或外置卷。Documents/Codex 和 Documents/ChatGPT 仅用于有限层级入口发现，确认具体项目后才递归。扫描预算为 1200 秒，报告 Codex 总占用、按位置和项目拆分、最大三项保留内容及真实覆盖缺口。扫描、默认清理入口、日报入口、报告模板和进程控制工具都在本目录内，不依赖父仓库运行时文件。

## 只读检查

```sh
python3 scripts/scan_codex.py \
  --home "$HOME" \
  --workspace "$HOME/.codex/skill-workspaces/codex-storage-cleanup/manual-YYYYMMDD" \
  --scan-mode full --no-inventory
```

默认清理入口先输出计划；带 `--apply` 才执行三类默认策略：

```sh
python3 scripts/apply_cleanup.py --home "$HOME"
python3 scripts/apply_cleanup.py --home "$HOME" --apply
```

它会直接删除有真实输入/生成证据的可再生缓存、编译缓存、中间产物和冗余旧构建（每个项目保留最新完整可用的一份）；定稿 worktree 也必须满足整个关联组连续超过 168 小时没有文件和相关会话活动，并通过句柄、引用和 Git 检查，才会移动到 `/Volumes/T1/Agent/archive/storage-observatory/worktrees`，校验后移除本机副本并保留原路径软链接；对超过 7 天的归档会话，以及有明确结束标记、无支持引用的旧交付物，先备份校验再删除本机精确路径。移动后的工作树锁定以保护离线登记；连接 T1 后从原路径继续打开、修改和提交，共享 Git 元数据留在本机。

每日入口使用固定历史目录：

```sh
python3 scripts/daily_codex_health.py --home "$HOME"
```

默认位置是 `$HOME/.codex/skill-workspaces/codex-storage-cleanup/daily`。每日入口只写检查器自己的 JSON、HTML 和历史摘要，不删除、移动或迁移用户文件。若容量数据已经写出但最后的 HTML 收尾超时，失败记录仍保留已测容量和大白话部分报告，同时保留上一份成功摘要。

## 自动化边界

默认目标是北京时间每天 09:00 的只读检查。覆盖安装并取得单独授权后，才通过宿主提供的产品自动化入口创建或更新任务；当前候选包不会改写 launchd、crontab 或 Codex 内部状态文件。若宿主没有可用入口，交付记录会保留任务说明、阻塞原因和解除条件，不把“准备好入口”写成“已运行”。

## 旧路径兼容

Codex 存储清理的实际入口、脚本和元数据均在本独立目录中。旧路径 `storage-observatory/subskills/codex-storage-cleanup` 仅作为迁移兼容别名，供现有自动化继续读取；维护和手动调用时使用本目录。存储观察站仓库里的旧日报入口仅转发到本 Skill，不包含另一份扫描实现。

版本：`2.1.4`
