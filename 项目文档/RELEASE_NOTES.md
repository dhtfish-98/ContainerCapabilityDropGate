# 候选版本记录

## v0.1.0 本地候选

- 对 OCI 创建与 exec 配置的五组 capability 实施显式白名单预检。
- `run-exec` 使用私有临时配置调用指定 runc，避免检查文件与传入文件分离。
- 在真实 ARM64 Linux 虚拟机内验证容器进程、子进程与 OCI exec；保留合成弱化配置和允许白名单对照。
- 仅完成本地验证；尚无正式版本标签、公开 CI 或 GitHub Release。
