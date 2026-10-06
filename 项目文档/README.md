# ContainerCapabilityDropGate

维护者：**dhtfish98**。状态：本地研究候选，尚未发布正式版本。

本项目为自有 OCI 工作流提供能力白名单检查：创建容器前检查五组 capability 并生成受限 `config.json`；执行 `runc exec` 前检查独立的进程配置，并通过受控入口传给运行时。它不修改 runc，也不声称修复 runc 漏洞。

在隔离 ARM64 Linux 虚拟机中，合成的宽松容器持有 `CAP_NET_RAW`，进程及 `fork`/`exec` 子进程都能创建原始套接字。收紧后五组能力均为零，创建操作返回 `EPERM`；显式授予该能力的白名单容器仍能完成受控操作。运行中容器的 OCI exec 配置也有独立对照：受限配置被内核拒绝创建原始套接字，而绕过本门禁直接调用 runc 的合成宽松 exec 配置能重新获得该能力。这说明**必须让所有创建和 exec 调用都经过受控入口**；若操作者仍可直接调用 runc，本门禁不能约束那些调用。

从项目源码目录运行 `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests` 检查策略。真实 VM 验收从同一目录运行：

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_macos_vm.py \
  --build-root /absolute/path/to/workspace/Build
```

该命令需要 Apple silicon、macOS Virtualization.framework、固定摘要的 Alpine ARM64 内核/initramfs、Zig 和官方 runc v1.5.2 ARM64 测试二进制；这些依赖存于 `Build/环境`，不随本项目源码发行。运行回执、串口日志、临时镜像和二进制只写入 `Build/验证/ContainerCapabilityDropGate-20261006`。

`.github/workflows/verify.yml` 还准备了托管 Ubuntu 上的原生 Linux 内核/runc 实验，运行 `scripts/run_linux_host.py` 并校验官方 amd64 二进制摘要；它仍需在公开仓库的同一提交实际跑过，才能算托管 CI 实证。

CLI 支持 `prepare`、`check-exec` 与 `run-exec`。`prepare` 对已有 OCI 配置做拒绝式检查，只保留已请求且获白名单允许的能力，**不会因白名单存在而自动授予能力**；`run-exec` 把已检查的进程配置复制到私有临时文件并传给指定 runc。部署时应限制调用者直接访问运行时或替换 bundle 的权限，并把策略文件及运行时路径纳入自己的变更控制。项目没有覆盖其他 OCI 运行时、真实多租户集群、镜像供应链或生产环境。

来源、第三方权利及验收边界见同目录的 `ORIGIN.md`、`THIRD_PARTY.md`、`CVP_STATUS.md`。
