---
layout: single
title: LKM unhide
excerpt: "How to find hidden LKM Rootkits scanning kernel memory."
date: 2024-06-19
classes: wide
header:
    teaser: /assets/images/lkm_unhide/demo.png
    teaser_home_page: true
author: sapellaniz
categories:
  - REM
tags:
  - Malware
  - RE
  - REM
sidebar:
  - title: "Title"
    image: "/assets/images/bio-photo.jpg"
---

![](/assets/images/lkm_unhide/demo.png)

How to find hidden LKM Rootkits scanning kernel memory.

---

# Table of Contents
1. [Evasion](#evasion)
2. [Detection](#detection)
3. [LKM unhide](#lkm_unhide)
4. [Prevention](#prevention)  


# Evasion

Many LKM Rootkits (diamorphine, reptile, etc) try to stay hidden removing themselves from the kernel module list using the list_del() function:
```c
list_del(&THIS_MODULE->list);
```

| ![](/assets/images/lkm_unhide/diamorphine_list_del.png) |
|:--:|
| *diamorphine* |

| ![](/assets/images/lkm_unhide/reptile_list_del.png) |
|:--:|
| *reptile* |

To remove the above mentioned or similar hidden LKM Rootkits, they must first be unhidden using the list_add() function:
```c
list_add(&THIS_MODULE->list, THIS_MODULE->list.prev);
```  


# Detection

list_del() function is defined at "include/linux/list.h":

| ![](/assets/images/lkm_unhide/source_list_del.png) |
|:--:|
| *"include/linux/list.h" source code* |

The poisoned pointers, LIST_POISON1 and LIST_POISON2 (0xdead000000000100 and 0xdead000000000122 on my computer), could be used to scan the kernel memory and find hidden modules. Once these poisoned pointers are found, it is possible to locate the pointer to the module structure and finally add the module to the kernel module list.

The module struct is defined at "include/linux/module.h":

| ![](/assets/images/lkm_unhide/struct_module.png) |
|:--:|
| *"include/linux/module.h" source code* |

list_head is the second member of the module struct. In a hidden module, the members of the list_head struct are the poisoned pointers (entry->next & entry->prev). Then is as simple as find a memory address wich contains LIST_POISON1 and check if just after that is LIST_POISON2. In that case the pointer to the hidden module would be just before LIST_POISON1.

It is not necessary to scan all kernel memory. It is usually sufficient to scan the memory regions between unhidden modules. Furthermore, when loading an LKM, memory is reserved using kmallok(). That means that when loading an LKM on an infected machine, it will most likely be assigned a higher memory address than any other module (including hidden LKM rootkits). The latter is not always the case, but in those cases hidden modules can be found by scanning some addresses beyond the LKM loaded in the highest address.  

  
# lkm_unhide

I have built **LKM unhide**, a LKM Rootkits Detection Tool which applies the detection technique explained above to add to the kernel module list any hidden module (that used list_del() to hide itself). You can find the code in [this repo](https://github.com/sapellaniz/lkm_unhide). Here is a quick demo:
 
| ![](/assets/images/lkm_unhide/demo.png) |
|:--:|
| *lkm_unhide demo* |

  
# Prevention

The main protections against this kind of malware are:

- **Secure boot & LKM signing**: Secure boot is a feature that ensures that only signed and trusted components, including kernel modules, can be loaded during the system boot process. It prevents the loading of unauthorized modules.
- **Linux Security Modules**: Use access control mechanisms such as AppArmor and SElinux to limit which processes and users can load and interact with kernel modules.
- **Block kernel module loading**: While it is possible to block kernel module loading, it is not recommended because the operating system would have to include all possible anticipated functionality compiled directly into the base kernel.
