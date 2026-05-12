#!/bin/bash
# Network Guard 插件 - 宿主机定时任务安装脚本
# 使用方法: 在宿主机上执行: bash install.sh
# 或者在宿主机 SSH 终端中执行

# 检测网卡
IFACE=""
for iface in eno1-ovs eno1 eth0 ens33 br0; do
    if ip addr show $iface &>/dev/null && ip addr show $iface | grep -q "inet 192"; then
        IFACE=$iface
        break
    fi
done

if [ -z "$IFACE" ]; then
    echo "❌ 未找到连接局域网的网卡，请手动指定"
    echo "可用的网卡:"
    ip link show | grep -E "^[0-9]" | awk -F': ' '{print $2}'
    exit 1
fi

echo "✅ 检测到网卡: $IFACE"

# 共享目录路径（与 AstrBot 容器的 /AstrBot/data 对应）
SHARE_DIR="/vol1/@appdata/astrbot/data"

# 写入 crontab
CRON_JOB="*/1 * * * * ip neigh show | grep $IFACE | grep lladdr | grep -iv fe80 | grep -iv FAILED | grep -iv PERMANENT > $SHARE_DIR/arp_cache.txt"

# 备份原有 crontab
crontab -l 2>/dev/null > /tmp/cron_backup_$$.txt

# 检查是否已存在相同任务
if grep -q "arp_cache.txt" /tmp/cron_backup_$$.txt; then
    echo "ℹ️ 定时任务已存在，跳过"
else
    echo "$CRON_JOB" >> /tmp/cron_backup_$$.txt
    crontab /tmp/cron_backup_$$.txt
    echo "✅ 定时任务已添加"
fi

rm -f /tmp/cron_backup_$$.txt

# 立即执行一次
echo "🔄 立即执行首次扫描..."
ip neigh show | grep $IFACE | grep lladdr | grep -iv fe80 | grep -iv FAILED | grep -iv PERMANENT > $SHARE_DIR/arp_cache.txt
echo "✅ 首次扫描完成，$(wc -l < $SHARE_DIR/arp_cache.txt) 个设备"

echo ""
echo "📋 安装完成！请重启 AstrBot 容器加载插件。"
