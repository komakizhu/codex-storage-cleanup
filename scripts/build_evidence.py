"""Read-only source/build inspection and one-build-per-project retention.

No build commands or downloads are executed. Branches and compilation profiles
do not create extra retention groups. Source, dependency downloads and active
outputs remain intact.
"""
from __future__ import annotations

import json
import os
import re
import filecmp
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
from functools import lru_cache
import ast

# Resolve the bundled helper first; the standalone package must work without
# the parent storage-observatory checkout being present.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import bounded_process


def static_js_config(text):
    """Accept literal exported configuration only; never evaluate JavaScript.

    Comments and strings cannot create properties. Expressions, spreads,
    functions and indirection are unsupported rather than deletion evidence.
    """
    pattern = re.compile(r'''\s+|//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[A-Za-z_$][\w$]*|-?\d+(?:\.\d+)?|[{}\[\]():,;.]''')
    tokens = []
    position = 0
    while position < len(text):
        match = pattern.match(text, position)
        if not match:
            raise ValueError('前端配置包含未支持表达式，不能证明输出目录')
        token = match.group()
        position = match.end()
        if token.isspace() or token.startswith(('//', '/*')):
            continue
        tokens.append(token)
    try:
        start = next(index + 2 for index in range(len(tokens) - 1) if tokens[index:index + 2] == ['export', 'default'])
    except StopIteration:
        raise ValueError('前端配置不是可静态确认的 export default 对象')
    index = start
    wrapped = tokens[index:index + 2] == ['defineConfig', '(']
    if start != 2 or wrapped:
        raise ValueError('包装函数、导出前表达式或间接配置未确认，不能证明输出目录')
    def value():
        nonlocal index
        if index >= len(tokens):
            raise ValueError('前端配置截断')
        token = tokens[index]
        index += 1
        if token == '{':
            result = {}
            while index < len(tokens) and tokens[index] != '}':
                key = tokens[index]
                index += 1
                key = ast.literal_eval(key) if key.startswith(('"', "'")) else key
                if index >= len(tokens) or tokens[index] != ':' or key in result:
                    raise ValueError('动态、简写或重复配置属性未确认')
                index += 1
                result[key] = value()
                if tokens[index:index + 1] == [',']:
                    index += 1
                elif tokens[index:index + 1] != ['}']:
                    raise ValueError('前端配置属性表达式未确认')
            if tokens[index:index + 1] != ['}']:
                raise ValueError('前端配置截断')
            index += 1
            return result
        if token.startswith(('"', "'")) or re.fullmatch(r'-?\d+(?:\.\d+)?', token):
            return ast.literal_eval(token)
        if token in ('true', 'false', 'null'):
            return {'true': True, 'false': False, 'null': None}[token]
        raise ValueError('前端配置值不是静态字面量，输出未检查')
    data = value()
    if not isinstance(data, dict):
        raise ValueError('前端配置不是静态对象')
    if wrapped:
        if tokens[index:index + 1] != [')']:
            raise ValueError('defineConfig 包装表达式未确认')
        index += 1
    if any(token != ';' for token in tokens[index:]):
        raise ValueError('导出后还有配置表达式，不能证明输出目录')
    return data


def command(args, cwd=None):
    try:
        result = bounded_process.run(args, cwd=cwd, capture_output=True, text=True,
                                timeout=12, env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"})
        return result.stdout.strip() if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


@lru_cache(maxsize=256)
def toml(path):
    try:
        import tomllib
        return tomllib.loads(Path(path).read_text())
    except ImportError:
        # macOS /usr/bin/python3 can be 3.9; use an installed stdlib parser,
        # never install a package or invoke a toolchain that might download.
        for binary in ("/opt/homebrew/bin/python3", "python3.14", "python3.13", "python3.12", "python3.11"):
            executable = shutil.which(binary)
            if executable and executable != sys.executable:
                out = command([executable, "-c", "import json,tomllib,sys; print(json.dumps(tomllib.load(open(sys.argv[1],'rb'))))", str(path)])
                if out is not None:
                    return json.loads(out)
        raise ValueError("需要本机 Python 3.11+ 的 TOML 解析器")
    except (OSError, ValueError) as error:
        raise ValueError(f"构建配置不可读：{path}: {error}")


def cargo_sources(manifest, seen=None):
    seen = set() if seen is None else seen
    manifest = manifest.resolve()
    if manifest in seen:
        return []
    seen.add(manifest)
    data = toml(str(manifest))
    sources = []
    root = manifest.parent
    if "package" in data:
        targets = [root / "src/main.rs", root / "src/lib.rs"]
        targets += [root / t.get("path", "src/main.rs") for t in data.get("bin", [])]
        if "lib" in data:
            targets.append(root / data["lib"].get("path", "src/lib.rs"))
        existing = [p for p in targets if p.is_file() and not p.is_symlink()]
        if not existing:
            raise ValueError(f"源码入口缺失：{manifest}")
        sources.extend(str(p) for p in existing)
    workspace = data.get("workspace", {})
    for pattern in workspace.get("members", []):
        members = list(root.glob(pattern))
        if not members:
            raise ValueError(f"workspace 成员缺失：{pattern}")
        for member in members:
            sources.extend(cargo_sources(member / "Cargo.toml", seen))
    # Local path dependencies are source, never disposable build data.
    sections = [data, workspace] + list(data.get("target", {}).values())
    for section in sections:
        for key in ("dependencies", "build-dependencies", "dev-dependencies"):
            for dep in section.get(key, {}).values():
                if isinstance(dep, dict) and "path" in dep:
                    sources.extend(cargo_sources(root / dep["path"] / "Cargo.toml", seen))
    if not sources:
        raise ValueError(f"没有可用源码：{manifest}")
    return sources


def cargo_output(path):
    """Recognize whole Cargo output roots, including custom --target-dir."""
    return (path / ".rustc_info.json").is_file() and any(
        (p / ".fingerprint").is_dir()
        for p in [path / "debug", path / "release", path / "dev"]
        + [p for p in path.glob("*/*") if p.name in {"debug", "release"}]
    )


def compiled_file(path):
    if not path.is_file() or path.is_symlink() or path.name.startswith('.'):
        return False
    if path.suffix in {'.rlib', '.dylib', '.so', '.a', '.exe', '.dll', '.o',
                       '.swiftmodule', '.swiftdoc', '.swiftinterface'}:
        return True
    if not path.suffix:
        # Copied builds can lose the executable permission bit.
        with path.open('rb') as stream:
            magic = stream.read(4)
        return magic in {b'\x7fELF', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf',
                         b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'} or magic[:2] == b'MZ'
    return False


def completed_output_file(path):
    """Return only a final Swift/Xcode output, not an intermediate module."""
    if path.is_dir() and path.suffix in {".app", ".framework", ".bundle", ".xctest"}:
        return True
    if not path.is_file() or path.is_symlink() or path.name.startswith('.'):
        return False
    if path.suffix in {'.o', '.rmeta', '.swiftmodule', '.swiftdoc', '.swiftinterface', '.d', '.dia'}:
        return False
    if path.suffix in {'.dylib', '.so', '.a', '.app', '.framework', '.bundle', '.xctest'}:
        return True
    try:
        with path.open('rb') as stream:
            magic = stream.read(4)
        return (
            magic in {b'\x7fELF', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'}
            or magic[:2] == b'MZ'
            or bool(path.stat().st_mode & 0o111)
        )
    except OSError:
        return False


def copied_resource(entry, project):
    """Tauri's bundled model/resources are disposable only if local originals remain."""
    config = project / 'tauri.conf.json'
    if not config.is_file():
        return False
    resources = json.loads(config.read_text()).get('bundle', {}).get('resources', {})
    if not isinstance(resources, dict):
        return False
    for source, destination in resources.items():
        if destination.rstrip('/') != entry.name:
            continue
        original = project / source.removesuffix('/**/*')
        if not original.is_dir() or original.is_symlink():
            continue
        if original.resolve().is_relative_to(entry.parent.parent):
            continue
        for output in entry.rglob('*'):
            counterpart = original / output.relative_to(entry)
            if output.is_symlink() or counterpart.is_symlink():
                return False
            if output.is_file() and (not counterpart.is_file() or not filecmp.cmp(output, counterpart, shallow=False)):
                return False
        return True
    return False


def inspect_artifact(path):
    path = Path(path)
    if path.is_symlink() or path.resolve() != path.absolute():
        raise ValueError("产物路径经过链接")
    repo_text = command(["git", "-C", str(path.parent), "rev-parse", "--show-toplevel"])
    if not repo_text:
        raise ValueError("未找到源码仓库，需读取该项目实际构建配置")
    repo = Path(repo_text)
    relative = path.relative_to(repo).as_posix()
    tracked = command(["git", "-C", str(repo), "ls-files", "--", relative])
    ignored = command(["git", "-C", str(repo), "check-ignore", "--", relative])
    if tracked is None or tracked:
        raise ValueError("目录包含 Git 跟踪文件或无法读取 Git 文件状态")
    cargo = cargo_output(path)
    if not ignored and not (cargo and (path / 'CACHEDIR.TAG').is_file()):
        raise ValueError("缺少项目忽略规则或完整 Cargo 缓存标记")
    common = command(["git", "-C", str(repo), "rev-parse", "--git-common-dir"])
    remote = command(["git", "-C", str(repo), "config", "--get", "remote.origin.url"])
    identity = str((repo / common).resolve()) if common else str(repo)
    # Clones of the same repository belong to the same project too.
    if remote:
        identity = remote.removesuffix(".git").replace("git@github.com:", "https://github.com/")
    profiles = []
    outputs = []
    sources = []
    if cargo:
        current = path.parent
        while not (current / "Cargo.toml").is_file() and current != repo:
            current = current.parent
        manifest = current / "Cargo.toml"
        sources = cargo_sources(manifest)
        if any(Path(source).resolve().is_relative_to(path) for source in sources):
            raise ValueError("源码入口位于拟删目录内，必须保留")
        profiles = [p for p in path.iterdir() if p.is_dir() and (p / ".fingerprint").is_dir()]
        profiles += [p for p in path.glob("*/*") if p.is_dir() and (p / ".fingerprint").is_dir()]
        allowed = {p.parts[len(path.parts)] for p in profiles} | {"doc", "tmp", "dev"}
        allowed |= {".rustc_info.json", "CACHEDIR.TAG", ".cargo-lock", ".DS_Store",
                    ".future-incompat-report.json", ".rustdoc_fingerprint.json"}
        if any(p.name not in allowed for p in path.iterdir()):
            raise ValueError("Cargo 目录中存在非标准顶层内容，需核实是否为用户文件")
        for profile in profiles:
            standard = {'.fingerprint', 'build', 'deps', 'examples', 'incremental', 'bundle',
                        '.cargo-lock', '.cargo-artifact-lock', '.cargo-build-lock', '.DS_Store'}
            for entry in profile.iterdir():
                if (entry.name in standard or entry.suffix in {'.d', '.pdb', '.dSYM', '.app', '.rmeta'}
                        or compiled_file(entry) or (entry.is_dir() and copied_resource(entry, current))):
                    continue
                raise ValueError(f"编译输出中混有无法识别的文件：{entry}")
        build = "cargo build --manifest-path " + shlex.quote(str(manifest)) + " --target-dir " + shlex.quote(str(path))
        kind = "Rust 编译产物"
    elif path.name == ".build" and (
        (path.parent / "Package.swift").is_file()
        or any(path.parent.glob("*.xcodeproj"))
        or any(path.parent.glob("*.xcworkspace"))
    ):
        project = path.parent
        package_manifest = project / "Package.swift"
        if package_manifest.is_file():
            swift_sources = [
                str(item) for folder in ("Sources", "Tests")
                for item in (project / folder).rglob("*.swift")
                if item.is_file() and not item.is_symlink()
            ]
            sources = [str(package_manifest)] + swift_sources
            if not swift_sources:
                raise ValueError("Swift 源码入口缺失")
            build = "swift build --package-path " + shlex.quote(str(project))
        else:
            sources = [
                str(item) for item in project.rglob("*.swift")
                if item.is_file() and not item.is_symlink() and ".build" not in item.parts
            ]
            if not sources:
                raise ValueError("Xcode/Swift 源码入口缺失")
            xcode_project = next(project.glob("*.xcodeproj"), None)
            if xcode_project is None:
                raise ValueError("Xcode 项目配置缺失")
            build = "xcodebuild -project " + shlex.quote(str(xcode_project)) + " -derivedDataPath " + shlex.quote(str(path))
        if not ignored:
            raise ValueError("Swift .build 缺少项目忽略规则")
        allowed = {
            "artifacts", "checkouts", "debug", "release", "repositories", "plugins",
            "prebuild", "workspace-state.json", "build.db", "build.db-shm", "build.db-wal",
        }
        if any(entry.name not in allowed for entry in path.iterdir()):
            raise ValueError("Swift .build 中存在无法识别的顶层内容")
        output_roots = [path / name for name in ("debug", "release")]
        output_roots += [candidate for candidate in path.glob("*/*") if candidate.name in {"debug", "release"}]
        outputs = [
            item for output_root in output_roots if output_root.is_dir()
            for item in output_root.rglob("*")
            if completed_output_file(item)
        ]
        if not outputs:
            raise ValueError("未找到已完成 Swift/Xcode 输出")
        dependency_entries = []
        for dependency_name in ("artifacts", "checkouts", "repositories", "plugins"):
            dependency_root = path / dependency_name
            if dependency_root.is_dir() and any(dependency_root.iterdir()):
                dependency_entries.append(str(dependency_root))
        if dependency_entries:
            raise ValueError("Swift .build 同时包含下载/依赖目录，不能把整个 .build 当作可删除构建；需先拆分输出范围：" + ", ".join(dependency_entries))
        kind = "Swift/Xcode 编译产物"
    elif (path.parent / "package.json").is_file():
        project = path.parent
        package = json.loads((project / "package.json").read_text())
        script = package.get("scripts", {}).get("build", "")
        dependencies = {**package.get("dependencies", {}), **package.get("devDependencies", {})}
        vite = "vite" in dependencies and "vite build" in script
        nextjs = "next" in dependencies and "next build" in script
        if not (vite or nextjs):
            raise ValueError("尚未识别前端构建命令与输出目录的对应关系")
        configs = list(project.glob("vite.config.*")) if vite else list(project.glob("next.config.*"))
        config_key = "outDir" if vite else "distDir"
        configured_outputs = []
        if len(configs) > 1:
            raise ValueError('多个前端配置，无法确认实际生效文件')
        for config in configs:
            data = static_js_config(config.read_text())
            build_config = data.get('build') or {}
            if vite and not isinstance(build_config, dict):
                raise ValueError('build 配置不是静态对象')
            output = build_config.get(config_key) if vite else data.get(config_key)
            if output is not None:
                if not isinstance(output, str):
                    raise ValueError('前端输出路径不是字符串字面量')
                configured_outputs.append((project / output).resolve())
        default_output = (project / ("dist" if vite else ".next")).resolve()
        if configured_outputs:
            if path.resolve() not in configured_outputs:
                raise ValueError("候选目录不是配置指定的前端输出目录")
        elif path.resolve() != default_output:
            raise ValueError("尚未识别前端构建命令与输出目录的对应关系")
        sources = [str(p) for folder in ("src", "app", "pages") for p in (project / folder).rglob("*")
                   if p.is_file() and not p.is_symlink() and p.suffix in {".ts", ".tsx", ".js", ".jsx", ".vue", ".svelte"}]
        if not sources:
            raise ValueError("前端源码入口缺失")
        if vite:
            outputs = list(path.glob("assets/*.js")) if (path / "index.html").is_file() else []
        elif (path / "BUILD_ID").is_file():
            outputs = [path / "BUILD_ID"]
        build = "cd " + shlex.quote(str(project)) + " && " + ("pnpm build" if (project / "pnpm-lock.yaml").is_file() else "npm run build")
        kind = "前端构建产物"
    else:
        raise ValueError("未识别为完整构建产物；需按项目构建配置确认，不能按目录名删除")
    # Successful output timestamps, not parent directory mtimes, choose the keeper.
    outputs += [p for profile in profiles for p in profile.iterdir() if compiled_file(p)]
    latest = max((p.stat().st_mtime for p in outputs), default=0)
    return {"project_key": identity, "source_root": str(repo), "source_entries": sources,
            "source_revision": command(["git", "-C", str(repo), "rev-parse", "HEAD"]),
            "rebuild_command": build, "artifact_type": kind,
            "latest_output_time": latest, "completed_outputs": [str(p) for p in outputs],
            "rebuild_basis": "本地源码入口、构建配置、Git 非跟踪状态及工具产物结构已核实；未实际重新编译",
            "network_cost": "保留全部下载缓存；缺失依赖仍可能需要下载，未执行联网检查",
            "rebuild_time": "需要重新编译；耗时未测量"}


def decide_builds(items, activity_check):
    groups = {}
    for item in items:
        if item.get("review_priority") != "old-artifact":
            continue
        try:
            evidence = inspect_artifact(item["path"])
        except (ValueError, OSError, TypeError, KeyError) as error:
            item["recommendation"] = "暂不处理：" + str(error)
            item["review_error"] = str(error)
            continue
        item.update(evidence)
        item["reason"] = evidence["rebuild_basis"]
        item["provenance"] = "工作区内的生成目录；源码仓库：" + evidence["source_root"]
        groups.setdefault((item["home"], evidence["project_key"]), []).append(item)
    for group in groups.values():
        completed = [item for item in group if item["latest_output_time"]]
        if not completed:
            for item in group:
                item["recommendation"] = "保留：未找到可保留的已完成构建输出"
            continue
        # A recently regenerated frontend bundle must not replace the project's
        # last native application build. Frontend-only projects still retain one.
        native = [item for item in completed if item["artifact_type"] == "Rust 编译产物"]
        keeper = max(native or completed, key=lambda item: (item["latest_output_time"], item["path"]))
        for item in group:
            item.pop("review_error", None)
            item["retained_path"] = keeper["path"]
            item["trash_paths"] = []
            if not item.get("latest_output_time"):
                item.update(
                    tier="protected",
                    review_priority="incomplete-build",
                    recommendation="保留：这是未完成或未确认成功的新构建，不能替代已完成保留项，也不能按旧目录清理。",
                    retention="incomplete",
                )
                continue
            if item is keeper:
                item.update(tier="protected", default_action="retain",
                            recommendation="保留该项目最新一份构建产物", retention="latest")
                continue
            active, note = activity_check(Path(item["path"]))
            item.update(active=active, activity=note)
            if active is not False:
                item.update(tier="protected", default_action="retain",
                            recommendation="保留：产物正在使用或使用状态检查失败", retention="active")
                continue
            item.update(tier="regenerable", review_priority="delete-old-build",
                        default_action="direct-delete", trash_paths=[item["path"]],
                        recommendation="建议删除整个旧编译目录；源码与下载缓存保留，需要时从本地源码重建。最新一份保留在：" + keeper["path"])
    return items
