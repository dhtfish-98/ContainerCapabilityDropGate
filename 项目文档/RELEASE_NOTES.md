# 版本说明

## v0.1.0

- 对 OCI 创建与 exec 配置的五组 capability 实施显式白名单预检。
- `run-exec` 使用私有临时配置调用固定摘要的官方 runc，避免检查文件与传入文件分离。
- exec 能力同时受全局策略与可信创建配置约束，不会因全局白名单较宽而恢复创建时未请求的能力。
- `run-exec` 仅接受 root 拥有且不可被其他用户写入的专用 `--private-root`、固定路径的运行时和状态目录，以及对应容器 ID 的受保护创建记录；该入口只供可信管理员使用。
- 对重复 JSON 键、非有限数值及数值溢出做拒绝式处理，阻止非标准 JSON 输出。
- 在真实 ARM64 Linux 虚拟机内验证容器进程、子进程与直接传递配置的 OCI exec；保留合成弱化配置和允许白名单对照。该 VM 实验不证明 `run-exec` CLI 或创建记录绑定。
- [公开主分支 CI 运行 37395992716](https://github.com/dhtfish-98/ContainerCapabilityDropGate/actions/runs/37395992716)在提交 `5879081272bb5f5014a3e3f1bd4e442f38539523` 上通过原生 Linux `run-exec` 正控、越权拒绝负控及直接 runc 对照。发行提交或标签须核对各自的同提交运行；生产创建记录绑定与 CVP 资格仍待独立验证。
