# 不砖设备的分阶段上线流程

不要第一次 OTA 就同时打开 `MODULE_SIG_FORCE`、`modules_disabled=1`、删除
capabilities、设置 immutable 和裁剪 `/dev/mem`。应按下列阶段推进，每一阶段都
保留 A/B 回滚。

## 阶段 0：盘点和信任根

1. 确认 SoC 是否支持 Secure Boot/熔断、安全启动 ROM、外部启动禁用和 eMMC/RPMB
   保护。
2. 建立离线签名 CA/HSM；模块签名私钥和 OTA/FIT 私钥不进入网关镜像。
3. 部署 U-Boot FIT 签名、冗余 environment、bootcount 和 A/B 槽。
4. 先验证“坏 OTA → bootlimit → 自动回旧槽”，再做安全策略。

完成标准：连续 20 次异常断电升级和 3 次健康检查失败均能回到可用槽。

## 阶段 1：审计模式

目标内核：

```kconfig
CONFIG_MODULES=y
CONFIG_MODULE_SIG=y
# CONFIG_MODULE_SIG_FORCE is not set
CONFIG_MODULE_SIG_ALL=y
CONFIG_DEVMEM=y
CONFIG_STRICT_DEVMEM=y
CONFIG_IO_STRICT_DEVMEM=y
```

临时不要设置 `modules_disabled=1`，`gw-init` 可用 `gw.mode=debug` 或审计版本。

采集：

```sh
# 已加载模块及签名状态
for m in /sys/module/*; do ...; done
modinfo <vendor>.ko | grep sig

# 哪些进程打开 /dev/mem、/dev/port、/proc/kcore
lsof /dev/mem /dev/kmem /dev/port /proc/kcore 2>/dev/null
fuser -v /dev/mem

# 启动期需要的 capability 和写路径
grep Cap /proc/self/status
auditctl -a always,exit -F arch=b64 -S init_module,finit_module -k modload
auditctl -w /dev/mem -p rw -k devmem
```

同时记录厂商安装脚本是否执行 `depmod`、`chattr`、`insmod`、`mknod`、写
`/lib/modules` 或访问 raw block 设备。

完成标准：形成必须签名的 ko 清单、必须保留的设备访问清单、必须可写的路径清单。

## 阶段 2：补齐签名和替代接口

- 所有随镜像发布的 ko 均由 OEM key 签名并通过 `modinfo` 验证。
- 能编入内核的通用驱动改为 `=y`，减少 ko 数量和签名存储。
- 依赖 `/dev/mem` 的厂商工具迁移到：
  - 标准 sysfs/ioctl；
  - 厂商驱动；
  - OEM 签名的窄地址白名单 broker；
  - 或仅在签名调试镜像中提供。
- 证书和关键配置迁移到只读/dm-verity 卷或双签名槽。

完成标准：干净系统启动后没有未签名模块；生产业务全流程不打开 `/dev/mem`。

## 阶段 3：单策略灰度

一次只打开一类限制，并在同型号测试柜执行断电、重启、驱动重载、OTA、串口登录、
厂商工具和调试流程：

1. `module.sig_enforce=1` + `CONFIG_MODULE_SIG_FORCE=y`；
2. `gw-init` 加载 `early-modules` 后写 `modules_disabled=1`；
3. immutable + 丢弃 `CAP_LINUX_IMMUTABLE`；
4. 丢弃 `CAP_SYS_MODULE/SYS_RAWIO/SYS_PTRACE`；
5. 打开 Yama、sysctl 和 BPF 限制；
6. 生产内核改为 `# CONFIG_DEVMEM is not set`；
7. 启用 dm-verity 和只读文件系统；
8. 最后启用 LoadPin/SELinux 等额外 MAC 策略。

每一步都更新 `gw-boot-confirm` 的健康检查。任何关键服务失败都不要 mark-good，
让 bootcount 触发回滚。

## 阶段 4：小批量现场

- 选择可远程回收日志、交通成本低的少量网关；
- 保留 OEM 签名调试 USB/recovery；
- 监控 `overall=degraded`、模块签名失败、verity corruption 和 bootcount；
- 至少覆盖一个完整采集周期、证书更新周期和厂商驱动版本。

## 阶段 5：全量和密钥/吊销预案

- 固化生产内核 fragment 和镜像 SBOM；
- 制定模块签名 key 轮换、厂商证书吊销和紧急 OTA 流程；
- 明确现场调试申请、设备绑定、有效期和审计记录；
- 定期在 QEMU/备用硬件验证旧 A/B 槽和 recovery 镜像仍可启动。

## 紧急解锁原则

不要在生产二进制中硬编码通用密码。推荐顺序：

1. 重启进入 OEM 签名 recovery/调试 FIT；
2. 使用设备绑定、短期有效的挑战-响应令牌；
3. 调试镜像只开放完成工单所需能力；
4. 所有解锁事件写入远端审计或持久安全日志。
