# 工业网关纵深防护参考实现

面向“现场人员可接触串口并拥有管理员账号”的嵌入式 Linux 网关。目标不是用一个
自定义程序对抗已经获得 root 的攻击者，而是建立几条相互独立的内核强制边界：

1. **信任链**：U-Boot/FIT 安全启动校验内核、DTB 和根文件系统哈希。
2. **模块边界**：内核强制校验模块签名；正常启动完成后关闭模块加载并丢弃相关
   capability bounding set。
3. **物理内存边界**：生产内核不编译 `/dev/mem`、`/dev/kmem`、`/dev/port` 和
   `/proc/kcore`；调试能力只放在 OEM 签名的临时调试镜像中。
4. **文件完整性边界**：系统和证书使用只读文件系统 + dm-verity；可写文件上的
   immutable 标志配合一次性丢弃 `CAP_LINUX_IMMUTABLE`，使后续 root 也不能执行
   `chattr -i`。
5. **可恢复边界**：A/B 系统槽、U-Boot bootcount、冗余环境变量和健康检查确认，
   保证错误固件自动回滚而不是在客户现场变砖。

> 重要前提：如果 Bootloader 未锁定、安全启动未烧录公钥哈希、外部启动/烧录模式
> 未关闭，能物理接触串口/存储芯片的人仍可能重写整个启动链。下面的软件措施可以
> 阻止“登录后加载 ko、打开 `/dev/mem`、改证书/脚本”这类常见攻击，但不能替代芯片
> 级 Root of Trust、熔断 Secure Boot 和存储访问保护。

## 目录

| 路径 | 作用 |
|---|---|
| `configs/gateway_security.fragment` | 模块签名、Lockdown、内存设备裁剪、dm-verity 等内核配置片段 |
| `src/gw-init.c` | 极小 PID 1 包装器：加载早期模块、锁 sysctl/immutable、丢弃危险 capabilities，再执行真实 init |
| `rootfs/etc/gw/` | 早期模块、保护路径、额外 sysctl、启动确认配置 |
| `rootfs/usr/sbin/gw-boot-confirm` | 健康检查通过后清除 bootcount / 标记 A/B 槽成功 |
| `systemd/gw-boot-confirm.service` | 可选的 systemd 兜底确认单元 |
| `scripts/gw-sign-module` | 在受控构建服务器上调用内核 `sign-file` 签名厂商 ko |
| `kernel/gw_regbroker.c` | 可选的窄地址白名单寄存器 broker 内核模块模板，替代完整 `/dev/mem` |
| `boot/uboot-secure.fragment` | U-Boot FIT 签名、bootcount、冗余环境变量配置模板 |
| `boot/gw-boot.cmd` | bootcount + A/B 回滚启动逻辑模板 |
| `docs/ROLLOUT.md` | 从审计模式到强制模式的不砖设备上线步骤 |

## 总体启动流程

```text
芯片 ROM / SPL
   │ 校验 U-Boot / FIT 公钥与签名
   ▼
U-Boot：bootcount + A/B 选择
   │ 校验 fitImage 中 kernel/DTB/initramfs 签名
   │ dm-verity root hash 位于已签名 FIT/DTB/cmdline
   ▼
内核：module.sig_enforce=1 / lockdown=integrity
   │ 根文件系统 SquashFS/EROFS(只读) + dm-verity
   ▼
/sbin/gw-init（由 init=/sbin/gw-init 引入）
   │ 1. modprobe /etc/gw/early-modules
   │ 2. 锁定模块树和 /etc/gw/protected.list
   │ 3. modules_disabled=1，收紧 ptrace/BPF/dmesg 等
   │ 4. 从 bounding set 丢弃 SYS_MODULE/SYS_RAWIO/SYS_PTRACE/...
   ▼
/sbin/init 或 systemd
   │ 所有服务和串口登录都继承收紧后的 bounding set
   ▼
业务健康检查成功 → gw-boot-confirm → bootcount=0 / slot_ok=1
```

## 1. 内核配置

将片段合并到目标内核配置：

```sh
cp arch/arm64/configs/<board>_defconfig .config
scripts/kconfig/merge_config.sh .config \
    /path/to/gateway-hardening/configs/gateway_security.fragment
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- olddefconfig
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j"$(nproc)"
```

生产镜像至少确认：

```sh
zcat /proc/config.gz | grep -E \
  'MODULE_SIG(_FORCE|_ALL)?|DEVMEM|DEVKMEM|PROC_KCORE|LOCKDOWN|DM_VERITY'
```

关键项：

- `CONFIG_MODULE_SIG=y`
- `CONFIG_MODULE_SIG_FORCE=y`
- `CONFIG_MODULE_SIG_ALL=y`
- 内核命令行额外包含 `module.sig_enforce=1`
- 生产配置 `# CONFIG_DEVMEM is not set`
- `# CONFIG_DEVKMEM is not set`
- `# CONFIG_DEVPORT is not set`
- `# CONFIG_PROC_KCORE is not set`
- `CONFIG_SECURITY_LOCKDOWN_LSM=y`、`CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y`
- `CONFIG_DM_VERITY=y` + 只读 SquashFS/EROFS

模块签名校验必须使用内核/PKCS#7 的成熟实现，**不要自己在 C 或 shell 里重新实现
RSA/ECDSA 校验**。自研校验很容易被绕过，也会增加存储和维护成本。

## 2. 安装 gw-init

交叉编译：

```sh
make CROSS_COMPILE=aarch64-linux-gnu-
make DESTDIR=/path/to/rootfs install
```

在已构建的 rootfs 中确保内核命令行包含：

```text
init=/sbin/gw-init ro rootwait module.sig_enforce=1 \
lockdown=integrity gw.mode=secure
```

`gw-init` 必须是 PID 1 包装器。普通启动脚本运行时已经无法修改 PID 1 及其它登录
会话的 capability bounding set；只有在 exec 真实 init 前由 PID 1 丢弃，后续所有
子进程才会永久继承该限制。

它会丢弃：

- `CAP_SYS_MODULE`：即使没有 `modules_disabled`，root 也不能加载模块；
- `CAP_SYS_RAWIO`：提高 `/dev/mem`、IO 端口和原始设备操作门槛；
- `CAP_SYS_PTRACE`：阻止进程注入和内存读取；
- `CAP_LINUX_IMMUTABLE`：设置完 immutable 后，任何人都不能再执行 `chattr -i`；
- `CAP_PERFMON`、`CAP_BPF`：收缩内核观察和可编程攻击面。

可以在设备上检查：

```sh
/sbin/gw-init status
capsh --print | grep -E 'sys_module|sys_rawio|sys_ptrace|linux_immutable'
cat /proc/sys/kernel/modules_disabled   # 1
```

在 musl + `-Os` 下，这个无外部库依赖的小程序通常只有十几到几十 KB；本仓库在
macOS/arm64 上的构建产物约 35 KB，仅用于语法和基础逻辑验证，实际体积以交叉
工具链和 strip 结果为准。

## 3. 关键文件和证书保护

### 推荐：只读系统卷 + dm-verity

- `/usr`、`/sbin`、`/lib/modules`、启动脚本、安全策略和信任根证书放入
  SquashFS/EROFS。
- 对该卷启用 dm-verity，root hash 放入已签名的 FIT/DTB 或内核强制命令行。
- 这样即使 root 直接 `dd` 写底层块设备，也无法同时伪造不在磁盘上的 verity root
  hash；读取被篡改块时会校验失败。

### 补充：immutable + 一次性丢弃修改能力

把实际路径加入 `/etc/gw/protected.list`。`gw-init` 在仍持有
`CAP_LINUX_IMMUTABLE` 时设置 `FS_IMMUTABLE_FL`，随后从 bounding set 删除该能力。
之后：

```sh
chattr -i /etc/gw/certs/ca.pem
# Operation not permitted
```

这比单独 `chmod 600` 或 `chattr +i` 强，因为普通 root 登录已经没有解除 immutable
所需的 capability。

但要清楚两个边界：

1. 如果块设备节点仍可写且攻击者能获得原始块写能力，纯 immutable 可被绕过；因此
   系统/证书卷仍应使用 dm-verity、只读文件系统或 SELinux 块设备写限制。
2. 证书需要轮换时，不要在原分区上开放一个 root 可调用的“解除只读”接口。应使用
   双证书槽/A-B 更新：OEM 签名证书包 → 写非活动槽 → 校验签名 → 原子切换 → 重启
   服务。业务程序还应使用内置 OEM CA/公钥校验证书和配置，使被替换的证书文件在
   应用层也不被信任。

采集数据库等高频写文件不适合设为 immutable。应分区分开：系统/程序/证书只读，
数据分区可写但 `nodev,noexec,nosuid`。只允许追加的审计/事件文件可在
`protected.list` 中用 `append /path` 设置 `FS_APPEND_FL`，随后同样无法解除；
但 append-only 不能阻止追加伪造记录，因此采集记录还应逐条签名（密钥放 TPM/安全
元件更佳）、尽快上传或写入远端审计。本地 root 对可变数据的篡改最终要靠远端校验、
度量证明或 WORM/安全元件发现，不能假设只读权限能保护正在写入的数据库。

## 4. 厂商驱动更新流程

推荐流程是“厂商交付 → OEM 审核/重签名 → A/B 升级 → 启动健康确认”，而不是在现场
给管理员开放任意 `insmod`：

```sh
# 在受控构建服务器，而不是网关上执行：
KDIR=/path/to/exact/kernel/build \
  ./scripts/gw-sign-module \
  oem-module-signing.key \
  oem-module-signing.crt \
  vendor_driver.ko
```

然后：

1. 用与网关完全一致的内核源码和 `.config` 重建厂商驱动，确认 vermagic/ABI；
2. 用 OEM 模块签名私钥签名；公钥证书通过 `CONFIG_SYSTEM_TRUSTED_KEYS` 编入内核；
3. 把 `.ko` 放入 `/lib/modules/$(uname -r)/extra/` 并在构建期生成 `modules.dep`；
4. 随 A/B rootfs/OTA 包发布；
5. 新槽首次启动时由 `gw-init` 加载，随后自动设置 `modules_disabled=1`；
6. 业务和驱动测试通过后执行 `gw-boot-confirm`；失败达到 `bootlimit` 后 U-Boot
   自动回到旧槽。

如果直接信任厂商自己的证书，内核只能证明“它确实由该厂商签名”，不能表达 OEM 的
型号、版本或允许加载策略。更安全的做法是 OEM 重签名；若必须信任厂商 key，应把
厂商证书隔离、建立吊销流程，并考虑 LoadPin/IMA/SELinux 限制可加载路径。

已合法签名但有漏洞的旧模块可能被降级加载。由于正常启动后会
`modules_disabled=1`，且模块位于 dm-verity 卷中，现场无法在启动后插入旧模块；
OTA 还应删除旧槽中的问题模块、提升策略版本，或通过内核 revocation keyring/新
签名 key 完成吊销。

### 必须不重启加载驱动怎么办？

这会削弱“启动后彻底关闭模块加载”的保证。可选方案：

- 进入 OEM 签名的一次性 `gw.mode=update` 启动项，在内核仍强制签名的前提下由受控
  更新服务加载模块，完成后立即重启进入 secure 模式；
- 或保留 `CONFIG_MODULE_SIG_FORCE=y`，不设置 `modules_disabled`，但用 SELinux/
  LoadPin 只允许签名更新服务调用 `finit_module`，并记录审计。

不要为了方便把 `CONFIG_MODULE_SIG_FORCE` 关掉，也不要把 OEM 私钥放到网关。

## 5. 现场调试和底层访问

首选方案是**不把调试后门做进生产系统**：

- 发布一个 OEM 签名的调试 FIT/USB/initramfs；
- U-Boot 验证该镜像签名后从 USB/内存启动；
- 调试镜像中可设置 `CONFIG_DEVMEM=y`、`CONFIG_STRICT_DEVMEM=y`、
  `CONFIG_IO_STRICT_DEVMEM=y`，并包含 `devmem`、`strace`、逻辑分析/CAN 工具等；
- 可将镜像绑定设备硬件 ID、工单号和有效期，或使用挑战-响应签发；
- 调试结束拔下 USB/重启即回到生产 A/B 槽，调试能力不占用网关闪存。

`gw-init` 也支持已签名命令行中的 `gw.mode=debug`。在该模式下它不设置
`modules_disabled`、不丢弃 capabilities、不设置 immutable，但内核模块签名强制
仍然有效。**只有当 `gw.mode=debug` 位于被 FIT/安全启动保护的 DTB/cmdline 中时，
这个开关才可信。** 如果 U-Boot 环境变量可随意修改，攻击者可直接改成 debug 或
`init=/bin/sh`，因此必须：

- 将 bootargs 放入签名 FIT/DTB，或使用 `CONFIG_CMDLINE_FORCE`；
- 锁定 U-Boot 串口提示和环境变量；
- 启用冗余 U-Boot environment；
- 有条件时熔断 Secure Boot、关闭外部烧录启动。

如果生产业务确实需要访问某几个寄存器，不要开启完整 `/dev/mem`。可参考
`kernel/gw_regbroker.c` 提供一个 OEM 签名的精简内核 broker 驱动：

- 只允许构建时白名单中的物理地址区间、宽度和 ioctl；
- 不允许访问 DDR、内核内存、IOMMU/启动控制寄存器；
- misc 设备节点默认 `0600`，并可由 udev/SELinux 进一步限制调用进程；
- 驱动本身随版本走签名和 A/B 更新。

该文件是需按板级寄存器表修改并在目标内核树中编译的模板，不参与主机端
`make check`。

## 6. 小存储和防砖设计

存储建议按代价从低到高选择：

1. **最低成本**：只读 SquashFS + immutable 策略 + bootcount/recovery；
2. **推荐**：压缩 A/B SquashFS/EROFS + dm-verity + 独立 recovery；
3. **高安全**：A/B + dm-verity + TPM/安全元件做度量和密钥保护。

空间预算经验：

- `gw-init`：无第三方库，musl 裁剪后通常十几到几十 KB；
- 模块签名证书：约 1–2 KB；每个 ko 的 PKCS#7 签名可能增加约 1 KB 到数 KB，
  因此只把真正可插拔的厂商驱动做成模块，其余驱动 `=y` 编入内核；
- dm-verity hash tree：通常约为数据卷的 1% 量级，具体取决于块大小和算法；
- A/B 双槽会占用两份压缩 rootfs，但这是避免 OTA/策略错误砖机最有效的成本；
- 调试工具放 USB/网络拉取的签名 initramfs，不占用网关固定存储。

防砖规则：

- 先发布“只审计不拦截”的内核/策略版本，收集未签名模块、`/dev/mem` 依赖、
  immutable 误路径和 capability 依赖；
- 所有强制策略先在实验槽/QEMU/同型号测试柜验证；
- OTA 写非活动槽，不要在线覆盖当前 rootfs；
- U-Boot 设置 `bootlimit=3`、`upgrade_available=1` 和 `altbootcmd`；
- 业务、采集、证书链和云端/本地健康检查通过后才运行 `gw-boot-confirm`；
- 配合硬件 watchdog，内核 panic/业务死锁后自动重启并计入 bootcount；
- U-Boot environment 使用冗余扇区，避免写环境变量时掉电；
- 保留 OEM 签名 recovery 槽或可更换的签名调试 USB。

## 设备端负面验证

在测试设备或 QEMU 中执行，切勿直接在客户现场首次试验：

```sh
# 未签名模块应被内核拒绝；启动锁生效后应直接不允许加载
insmod hello.ko
dmesg | tail -n 20

# /dev/mem 应当不存在
ls -l /dev/mem /dev/kmem /proc/kcore

# immutable 能力应已从当前 bounding set 消失
chattr -i /etc/gw/certs/ca.pem

# 策略状态应输出 overall=secure，退出码为 0
/sbin/gw-init status
echo $?

# 启动确认会写入 bootcount=0 / upgrade_available=0
gw-boot-confirm
```

还应测试：

- 故意刷入未签名 ko：新槽健康检查失败并自动回滚；
- 故意把 `protected.list` 写成启动必需的可写文件：审计阶段发现，不进入强制版；
- OTA 中途断电：U-Boot 冗余环境和 A/B 槽可恢复；
- 串口修改 U-Boot 参数：FIT/DTB 或 `CMDLINE_FORCE` 应拒绝/忽略；
- 厂商旧版寄存器工具：确认是否依赖 `/dev/mem`，迁移到 broker 或签名调试镜像。

## 参考资料

- [Linux Kernel Module Signing Facility](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [U-Boot Boot Count Limit](https://docs.u-boot.org/en/v2025.10/api/bootcount.html)
- [U-Boot Verified Boot / FIT Signature Verification](https://docs.u-boot.org/en/latest/usage/fit/verified-boot.html)
