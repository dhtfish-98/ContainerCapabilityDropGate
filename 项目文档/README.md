# ContainerCapabilityDropGate

维护者：**dhtfish98**。状态：本地研究候选，尚未发布正式版本。

本项目为自有 OCI 工作流提供能力白名单检查：创建容器前检查五组 capability 并生成受限 `config.json`；执行 `runc exec` 前检查独立的进程配置，并提供管理员专用的 `run-exec` 入口。它不修改 runc，也不声称修复 runc 漏洞。

在隔离 ARM64 Linux 虚拟机中，合成的宽松容器持有 `CAP_NET_RAW`，进程及 `fork`/`exec` 子进程都能创建原始套接字。收紧后五组能力均为零，创建操作返回 `EPERM`；显式授予该能力的白名单容器仍能完成受控操作。运行中容器的 OCI exec 配置也有独立对照：预检通过的受限配置被内核拒绝创建原始套接字，而直接调用 runc 的合成宽松 exec 配置能重新获得该能力。此 VM 实验将配置直接传入 runc，**未运行 Python `run-exec` 入口**，所以不证明该入口的真实运行或完整生命周期绑定。若操作者仍可直接调用 runc，本门禁不能约束那些调用。

从项目源码目录运行 `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests` 检查策略。真实 VM 验收从同一目录运行：

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_macos_vm.py \
  --build-root /absolute/path/to/workspace/Build
```

该命令需要 Apple silicon、macOS Virtualization.framework、固定摘要的 Alpine ARM64 内核/initramfs、Zig 和官方 runc v1.5.2 ARM64 测试二进制；这些依赖存于 `Build/环境`，不随本项目源码发行。运行回执、串口日志、临时镜像和二进制只写入 `Build/验证/ContainerCapabilityDropGate-20261006`。

`.github/workflows/verify.yml` 还准备了托管 Ubuntu 上的原生 Linux 内核/runc 实验，运行 `scripts/run_linux_host.py`，校验官方 amd64 二进制摘要，并拟经 `run-exec` CLI 实际调用受保护的 runc。每次实验在 `/var/lib/container-capability-gate-tests/<run-id>` 新建独立 root 目录，遇到同名目录即拒绝，不复用部署状态；提权实验只允许 `main` 推送、`v*` 标签推送或维护者在这些受信 ref 手动触发，所有 PR 只跑非提权策略测试。部署公开工作流前，仓库管理员须保护 `main` 分支与发行标签并限制手动触发所选 ref；工作流条件只限制事件/ref，不替代仓库权限设置。该工作流仍需在公开仓库的同一提交实际跑过，才能算托管 CI 实证。

CLI 支持 `prepare`、`check-exec` 与 `run-exec`。`prepare` 对已有 OCI 配置做拒绝式检查，只保留已请求且获白名单允许的能力，**不会因白名单存在而自动授予能力**；输入会拒绝重复 JSON 键和非有限数值，输出仅使用标准 JSON 数值。`check-exec` 与 `run-exec` 还必须提供 `--created-spec`，以记录中的创建能力限制后续 exec 的能力请求。

`prepare` 只审查 capability 等本项目明确处理的字段；hooks、mounts、`root.path` 等其他 OCI 字段会原样保留。输入必须是已审查的可信自有 bundle，不能把此工具当作对任意不可信配置的全面隔离器。

用于实际启动的 `run-exec` 只供可信管理员直接运行，**不能把此 root 入口连同可自选参数委托给低权限用户或不受信请求**。`--private-root` 应指向部署者建立的专用目录，例如 `/var/lib/container-capability-gate`；整条目录链必须由 root 拥有、没有组/其他用户写权限且没有符号链接。入口只接受该目录下固定位置的官方 runc v1.5.2 摘要匹配文件 `runc`、`runtime-state` 及 `approved/<容器 ID>/config.json`，将已检查的进程配置写入私有临时文件再传给 runc。工作区 `Build` 只存编译与验证回执，不充当运行时信任根。`check-exec` 只是静态分析。工具没有创建容器的受控入口，不能单靠记录证明它等于运行中容器的真实创建配置；这个绑定、策略文件保护、限制直接调用 runc 和替换 bundle 的权限都属于部署者的待审集成。项目没有覆盖其他 OCI 运行时、真实多租户集群、镜像供应链或生产环境。

来源、第三方权利及验收边界见同目录的 `ORIGIN.md`、`THIRD_PARTY.md`、`CVP_STATUS.md`。
