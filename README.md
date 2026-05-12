# Network Guard - 内网设备监控守卫

[![AstrBot](https://img.shields.io/badge/AstrBot-v4.16+-blue)](https://github.com/Soulter/AstrBot)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

## 📖 简介

内网设备监控守卫是一个 AstrBot 插件，用于监控局域网设备接入情况。发现新设备或陌生设备时自动向管理员推送通知，支持对指定设备发起 ARP 攻击踢下线。

**适用场景：** 防止蹭网、监控未知设备接入、家庭网络安全管理。

---

## ✨ 功能

| 功能 | 说明 |
|------|------|
| 📡 **自动扫描** | 宿主机每分钟收集 ARP 信息，实时更新设备列表 |
| 🔔 **新设备通知** | 发现未记录过的设备时自动推送消息给管理员 |
| ⚠️ **陌生设备告警** | 发现白名单外的设备时自动告警 |
| ✅ **白名单管理** | 信任的设备不再告警 |
| ⚔️ **ARP 攻击** | 对指定设备发起 ARP 欺骗，使其断网 |
| 📋 **设备列表** | 随时查看局域网内所有在线设备及其 MAC 地址 |

---

## 📦 安装

### 前置条件

1. AstrBot >= v4.16
2. 宿主机（飞牛/群晖等 NAS）已安装 **cron**（通常默认已安装）
3. 宿主机与目标设备在同一局域网（`192.168.31.0/24` 或自定义网段）

### 安装步骤

**方法一：通过 AstrBot 插件市场安装（推荐）**

```
/plugin install network_guard
```

**方法二：手动安装**

1. 将 `astrbot_plugin_network_guard` 文件夹放入 AstrBot 的 `data/plugins/` 目录
2. 重启 AstrBot 容器
3. 在宿主机上设置定时任务（脚本在 `install.sh` 中）

### 🛠 宿主机定时任务配置

插件依赖宿主机定时写入 ARP 信息到共享文件。执行以下命令：

```bash
# 设置 crontab，每1分钟更新 ARP 信息
echo '*/1 * * * * ip neigh show | grep eno1-ovs | grep lladdr | grep -iv fe80 | grep -iv FAILED | grep -iv PERMANENT > /vol1/@appdata/astrbot/data/arp_cache.txt' | crontab -
```

> **注意：** 如果网络接口不是 `eno1-ovs`，请改为宿主机实际连接局域网的网卡名（可用 `ip addr` 查看）。

---

## 📟 指令列表

| 指令 | 说明 |
|------|------|
| `内网扫描` | 立即扫描局域网，列出所有在线设备 |
| `内网列表` | 查看已记录的设备列表（含白名单标记） |
| `内网信任 <MAC地址> <名称>` | 将设备加入白名单，不再告警 |
| `内网移除 <MAC地址>` | 从白名单中移除 |
| `内网攻击 <IP地址> [秒数]` | 对指定 IP 发起 ARP 攻击踢下线（默认 60 秒） |
| `内网停止 <IP地址>` | 尝试恢复指定设备的网络连接 |
| `内网帮助` | 显示帮助信息 |

### 指令示例

```
内网扫描
内网列表
内网信任 cc:da:20:49:b1:b7 我的笔记本
内网攻击 192.168.31.105 120
内网停止 192.168.31.105
```

> **注意：** 无需 `/` 前缀。如果配置了 `wake_prefix`，请直接发指令名称，不要带前缀。

---

## ⚙️ 配置

插件配置通过 `data/plugins/network_guard/config.json` 管理，也可以通过指令修改：

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `notify_session` | `93E7D4D47A1...` | 通知推送的目标会话 ID |
| `scan_interval` | `10` | 自动扫描间隔（分钟） |
| `notify_on_new` | `true` | 发现新设备时是否通知 |
| `known_devices` | `[]` | 白名单 MAC 地址列表（格式: `aa:bb:cc:dd:ee:ff:名称`） |

---

## 🔧 工作原理

```
宿主机（飞牛/NAS）
  └─ cron（每1分钟）
       └─ ip neigh show → 写入共享文件 → /vol1/@appdata/astrbot/data/arp_cache.txt
                                          ↓
AstrBot 容器
  └─ plugin (network_guard)
       └─ 读取共享文件 → 解析设备列表 → 比对白名单 → 推送通知
```

> `arp_cache.txt` 文件通过 Docker 的 Volume 挂载实现主机与容器共享。

---

## ⚠️ 注意事项

- ARP 攻击功能仅适用于**你自己的局域网**，请勿用于非法用途
- AP 隔离或被攻击的目标可能受路由器防火墙影响无法正常工作
- 需要宿主机开放 SSH（用于 ARP 攻击），如果 SSH 连接失败可手动写命令到 `/tmp/arp_attack.sh`

---

## 📄 许可证

MIT License

Copyright (c) 2026 AstrBot
