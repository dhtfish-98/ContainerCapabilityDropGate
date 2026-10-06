# 项目来源与范围

- 维护者：dhtfish98。
- 自有实现：`src/container_capability_gate.py`、VM 验收脚本与受控探针。没有复制或移植 runc 源码；测试通过独立下载的官方 runc 可执行文件调用公开 OCI 接口。
- 选题所读固定上游：[`opencontainers/runc@ea8b6d42cd343dec21cfdaadbd139d805dfd1bfe`](https://github.com/opencontainers/runc/commit/ea8b6d42cd343dec21cfdaadbd139d805dfd1bfe)，关注 capability 配置、进程创建和 exec 路径。该固定源码提交是研究参考，不是本项目构建依赖，也不是漏洞证明。
- 真实本地实验运行时：官方 [`runc v1.5.2`](https://github.com/opencontainers/runc/releases/tag/v1.5.2) ARM64 静态 PIE 二进制，SHA-256 `d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0`。版本与上面的研究源码提交不同，应分别标注。
- 本项目的弱化配置是自建对照；不能归因于 runc 或任何第三方的默认配置。
