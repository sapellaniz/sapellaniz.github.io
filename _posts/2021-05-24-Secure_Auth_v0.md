---
title: norzhctf2021 - Secure Auth v0 
excerpt: "One of NorzhNuclea's developers joined the team last quarter, specialized in authentication systems he found one he developed a few years ago with a innovative obfuscation method. Find the correct password to validate the checks."
date: 2021-05-24
categories: [CTF, RE]
tags: [CTF, norzhctf2021, RE]
---

> One of NorzhNuclea's developers joined the team last quarter, specialized in authentication systems he found one he developed a few years ago with a innovative obfuscation method. Find the correct password to validate the checks.

---

# Análisis estático básico

Al descargar el archivo que nos adjuntan en el reto, lo primero que me sorprende es su peso:

```
$ ls -lh
-rwxr-xr-x 1 x    x     70M may 22 04:58 chall
```

Compruebo qué clase de archivo es:

```
$file chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=2d7a473fecb4f2cc06b09e9652f52db5b4605f67, for GNU/Linux 3.2.0, stripped
```

ELF de 64 bits, linkado dinámicmanete. Buscando cadenas de caracteres imprimibles en él, no encuentro gran cosa:

```
$ strings chall
...
c-n|TD^zJFp|I'q"VCj7.mNj4
f4|<eN3w$
Failed !
...
```


# Análisis dinámico básico

Compruebo las llamadas a librerias que hace el binario:

```
$ltrace ./chall
__isoc99_scanf(0x49c8031, 0x7ffdf6599610, 0x7ffdf6599768, 0x7f343dac2598AAAA
)                                             = 1
strlen("AAAA")                                                                                                        = 4
strcmp("'T=\\", "c-n|TD^zJFp|I'q"VCj7.mNj4")                                                                          = -60
puts("Failed !"Failed !
)                                                                                                      = 9
+++ exited (status 1) +++
```

Parece que le hace algún tipo de transformación a la cadena que le pasamos al binario antes de compararla con la cadena "c-n|TD^zJFp|I'q"VCj7.mNj4"


# Análisis estático avanzado

Al intentar desensamblarlo, radare2 tarda basatante más de lo normal. Intento depurarlo con gdb y me doy cuenta de que entre cada instrucción hay miles de NOPs, echo un ojo a los bytes del binario para confirmarlo:

```
$ xxd chall
...
001c5900: 9090 9090 9090 9090 9090 9090 9090 9090  ................
...
001deb60: 9090 9090 9090 9090 9090 9090 9090 9090  ................
```

Depurar este binario es algo enormemente ineficiente debido a su nivel de ofuscación. Para tratar de obtener las instrucciones "útiles" desensamblo el binario:

```
$ objdump -d -M intel chall | grep -v nop | tee disass.txt
...
```

Tarda un rato pero porfín obtendo las instrucciones que me interesan, menos de 270 en un binario de 70MB.

A continuación adjunto la parte interesante del binario, que es la que transforma la cadena que le pasamos antes de compararla con la extraña cadedna hardcodeada.

```
 1f46549:       0f be 04 08             movsx  eax,BYTE PTR [rax+rcx*1]
 1facfb9:       83 f8 20                cmp    eax,0x20
 2013bfb:       0f 8e cf e6 c6 00       jle    2c822d0 <__isoc99_scanf@plt+0x2881270>
 20e0f08:       48 8b 45 f8             mov    rax,QWORD PTR [rbp-0x8]
 2147b91:       48 63 4d f0             movsxd rcx,DWORD PTR [rbp-0x10]
 21ae582:       0f be 04 08             movsx  eax,BYTE PTR [rax+rcx*1]
 221505c:       83 f8 7f                cmp    eax,0x7f
 227b94c:       0f 8d 7e 69 a0 00       jge    2c822d0 <__isoc99_scanf@plt+0x2881270>
 2348cdc:       48 8b 45 f8             mov    rax,QWORD PTR [rbp-0x8]
 23af83d:       48 63 4d f0             movsxd rcx,DWORD PTR [rbp-0x10]
 2416471:       0f be 04 08             movsx  eax,BYTE PTR [rax+rcx*1]
 247cf90:       83 e8 21                sub    eax,0x21
 24e383b:       89 45 ec                mov    DWORD PTR [rbp-0x14],eax
 254a273:       48 8b 0c 25 50 a0 9c    mov    rcx,QWORD PTR ds:0x49ca050
 254a27a:       04
 25b0d8b:       8b 45 f0                mov    eax,DWORD PTR [rbp-0x10]
 26177e7:       be 04 00 00 00          mov    esi,0x4
 267e31d:       99                      cdq
 26e4cfb:       f7 fe                   idiv   esi
 274b6ff:       8b 45 ec                mov    eax,DWORD PTR [rbp-0x14]
 27b2235:       48 63 d2                movsxd rdx,edx
 2818afa:       0f be 0c 11             movsx  ecx,BYTE PTR [rcx+rdx*1]
 287f631:       83 e9 21                sub    ecx,0x21
 28e6255:       01 c8                   add    eax,ecx
 294cbd5:       b9 5f 00 00 00          mov    ecx,0x5f
 29b3497:       99                      cdq
 2a19f4e:       f7 f9                   idiv   ecx
 2a80a2b:       83 c2 21                add    edx,0x21
 2b4e187:       48 8b 45 f8             mov    rax,QWORD PTR [rbp-0x8]
 2bb4c75:       48 63 4d f0             movsxd rcx,DWORD PTR [rbp-0x10]
 2c1b7b3:       88 14 08                mov    BYTE PTR [rax+rcx*1],dl
 2ce8f20:       e9 74 6a 06 00          jmp    2d4f999 <__isoc99_scanf@plt+0x294e939>
 2db64b0:       8b 45 f0                mov    eax,DWORD PTR [rbp-0x10]
 2e1ce68:       83 c0 01                add    eax,0x1
 2e8372d:       89 45 f0                mov    DWORD PTR [rbp-0x10],eax
 2eea00d:       e9 18 db d8 fe          jmp    1c77b2a <__isoc99_scanf@plt+0x1876aca>
 2fb7634:       5d                      pop    rbp
 3084d2e:       c3                      ret
```

Y a continuación muestro el funcionamiento de este algoritmo en python3:

**pseudo.py**

```python3
str1 = "c-n|TD^zJFp|I'q\"VCj7.mNj4"
str2 = "f4|<"
out = ""

flag = input()

for i in range(0, len(input)):
    if ord(c) > 0x1f and ord(c) < 0x80:
        n = ord(c) - 0x21
        n += (ord(str2[i%4]) - 0x21)
        n %= 0x5f
        n += 0x21
        out = ''.join((chr(n),out))
    if out != str1:
	print("Failed !")
```

Para escribir el solver, no puedo invertir el algoritmo por la operación "% 0x5f", paso cada caracter por el algoritmo y si coincide con el caracter correspondiente de la cadena hardcodeada, lo antepongo a la flag.

**solver.py**

```python3
#!/usr/bin/python3

import string

ct = "c-n|TD^zJFp|I'q\"VCj7.mNj4"
rara = "f4|<"
flag = ""

for i in range(0, len(ct)):
    for c in string.printable:
        if ord(c) > 0x1f and ord(c) < 0x80:
            n = ord(c) - 0x21
            n += (ord(rara[i%4]) - 0x21)
            n %= 0x5f
            n += 0x21
            if n == ord(ct[i]):
                flag = ''.join((c,flag))
                pass

print(flag)
```

Flag: NORZH{n0pfuscat3d_b1nary}
