# dist-claims

Find installed Python distributions that claim the same file or command, before
an uninstall or upgrade leaves an environment broken. Offline, read-only, and
without importing the packages under inspection. Python 3.11+, no runtime dependencies.

`pip check` checks dependency requirements. This tool compares `.dist-info/RECORD`
and console/GUI entry-point claims across explicitly supplied site directories.
It can expose ownership conflicts even when dependency versions are compatible.

## Install and try

```sh
git clone https://github.com/KanadeK/dist-claims.git
cd dist-claims
python -m venv .venv
# Linux/macOS:
.venv/bin/python -m pip install .
.venv/bin/dist-claims --version
# Windows PowerShell:
.venv/Scripts/python.exe -m pip install .
.venv/Scripts/dist-claims.exe --version
```

From the checkout you can also run `python dist_claims.py` without installing.
Create a disposable **synthetic** conflict:

```sh
python examples/make_demo.py demo-site
python dist_claims.py --site demo-site --json
```

Expect `shared-file`, two owners, `complete: true`, and exit status **1**.
Use your real environment's site-packages path as an explicit `--site` value.
Repeat `--site` for multiple install locations. The tool does not discover or
activate other environments and does not read package payloads.

```sh
python dist_claims.py --site /path/to/venv/lib/python3.13/site-packages --json
# Scan a Windows environment using its own case behavior (the default on Windows):
python dist_claims.py --site .venv/Lib/site-packages --case-insensitive --json
```

For untrusted environment metadata, use a **trusted external interpreter** and
`python -I -S /path/to/dist_claims.py --site /path/to/target/site-packages --json`.
Starting the target environment's interpreter normally can execute its startup
hooks before this program begins. The scanner itself never imports target packages.

## Findings and automation

| Code | Meaning |
|---|---|
| `shared-file` | More than one distribution claims one lexical canonical path |
| `shared-command` | Console/GUI entry points would use the same command name |
| `duplicate-distribution` | Multiple metadata directories have the same normalized project name |
| `duplicate-record-path` | A RECORD repeats a canonical path |
| `coverage-gap` | Missing, malformed, linked, unsupported, or over-budget metadata |

Exit **0** means no findings within a complete `.dist-info` scan; **1** means
review findings; **2** means invalid input or incomplete coverage. Incomplete
coverage takes precedence over findings. JSON schema version is `1`.

`different_hash_algorithms` lists hash algorithms whose *recorded values disagree*
between owners. Different algorithms alone are not comparable. Recorded hash or
size disagreement is metadata evidence; payload bytes are never verified.
Identical shared namespace files may be intentional and still need review.
Do not uninstall or delete files solely on this tool's findings.

## Limits, privacy, and cleanup

Version 0.1.0 handles regular `.dist-info` directories on a stable local
filesystem. Legacy `.egg-info` is reported as incomplete. It does not inspect
wheels, conda ownership, import precedence, actual installed executable content,
or dependency vulnerabilities. Symlink/junction metadata is rejected. File claims
are normalized lexically, so distinct symlink aliases are not combined. Windows
case-insensitive matching uses conservative Unicode casefold, not an NTFS emulator.

Budgets: 8 MiB per metadata file, 64 MiB total metadata, 500,000 RECORD rows,
10,000 distributions, and 1,000 displayed findings. Exceeded scan budgets fail
coverage; the findings cap preserves the total count and failure status.
Reports contain package names and absolute claim paths. Review before sharing.
No network requests, telemetry, automatic fixes, or filesystem writes occur.

Uninstall with `.venv/bin/python -m pip uninstall dist-claims` (Windows:
`.venv/Scripts/python.exe -m pip uninstall dist-claims`). Remove the disposable
`demo-site` and `.venv` directories when finished. No background service exists.

## Development and evidence

Run `python -m unittest discover -s tests -v`; see [CONTRIBUTING.md](CONTRIBUTING.md).
Tests create real metadata files and run the CLI with success, conflict and
incomplete exits. CI checks Linux/macOS/Windows with Python 3.11 and 3.13, builds
packages and installs the command. Check the actual Actions run for its result.

The failure mode is documented in [pip #8509](https://github.com/pypa/pip/issues/8509)
and [pip #3980](https://github.com/pypa/pip/issues/3980). The implementation follows
the [PyPA installed-project recording](https://packaging.python.org/en/latest/specifications/recording-installed-packages/)
and [entry-point](https://packaging.python.org/en/latest/specifications/entry-points/)
formats. It does not copy their implementations. MIT; [third-party notes](THIRD_PARTY.md).

## 中文说明

离线检查 Python 环境中多个发行包对同一文件或命令的归属声明，辅助排查卸载、
升级后的文件丢失。显式传入 `--site`，工具只读取元数据，不导入目标包、不修改环境。
返回码 0 表示本次完整扫描未发现问题，1 表示需复核的冲突，2 表示输入或覆盖不完整。
共享命名空间文件可能合法；结果用于调查，不自动修复。报告包含路径，分享前请检查。
