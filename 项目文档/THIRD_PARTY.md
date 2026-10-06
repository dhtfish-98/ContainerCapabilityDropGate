# 第三方权利

本项目测试时调用 `opencontainers/runc` 的官方 v1.5.2 二进制；该二进制和上游源码采用 Apache License 2.0。上游 [`LICENSE`](https://github.com/opencontainers/runc/blob/v1.5.2/LICENSE) 的完整文本保存在 `THIRD_PARTY_LICENSES/runc-APACHE-2.0.txt`，本地 SHA-256 为 `552a739c3b25792263f731542238b92f6f8d07e9a488eae27e6c4690038a8243`。项目自己的代码许可证见 `LICENSE`。

ARM64 Linux 内核和 Alpine initramfs、Zig 均为本地测试环境依赖，不打包在本项目源码或候选发行资产内。若将这些第三方二进制另行分发，应另行检查并保留各自许可证与声明。
