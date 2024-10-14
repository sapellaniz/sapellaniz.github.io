---
title: Circle City Con CTF2021 - Little Mountain 
excerpt: "Climb this mountain and score some points :)"
date: 2021-06-12
categories: [CTF, RE]
tags: [CTF, Circle City Con CTF2021, RE]
---
`Reversing`
>  Climb this mountain and score some points :)
---

# Primeros pasos

Para este se entrega un binario llamado "little":

```
$ file little
little: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=e351b1170c55d3a63fde69c338ff1b2911dd1d88, for GNU/Linux 3.2.0, not stripped
```

Ni con strings ni con strace se puede obtener información interesante, si se ejecuta aparece un menú con 3 opciones:

```
$ ./little
Option 0: Guess the number
Option 1: Change the number
Option 2: Exit
```

- La opción 0 imprime la cadena "Go ahead, give it a shot...", lee un entero e imprime la cadena "Try again?".

- La opción 1 solamente imprime la cadena "Always ready for more".

- La opción 2 termina la ejecución del programa.

# Análisis estático

Si se decompila con Ghidra, se puede ver el funcionamiento del main, que es la función que muestra las opciones y llama a las demás funciones. Estas funciones no son llamadas directamente sino que primero se obtiene su dirección de memoria de una estructura. Llama la atenciñón que hay 4 direcciones en esta estructura, esto quiere decir que se puede llamar a una 4ª función (opción 3).

También se pueden buscar las cadenas anteriores, y buscando las referencias a estas, encontrar rapidamente las funciones de las opciones 0, 1 y 2. Estas funciones se llaman 'a', 'b' y 'c' respectivamente, y la función "oculta" de la opción 3 se llama 'd'.

### a
![](/assets/img/ccc/01.png)

### b
![](/assets/img/ccc/02.png)

### c
![](/assets/img/ccc/03.png)

### d
![](/assets/img/ccc/04.png)

Parece que la función 'd' imprime la flag cuando la variable 'modded' tiene un valor de 20 (0x14). En este punto hay dos opciones:

- Poner un breakpoint en la comparación del valor modded y cambiar su valor a 20.

- La función 'b' incrementa 'modded' una unidad cada vez que se la llama, entonces podría ser llamada 20 veces y luego llamar a la función 'd' para que imprima la flag. 

A continuación se muestra el codigo de un script que resuelve el reto:

**solver.py**

```python
#!/usr/bin/python3

from pwn import *

b = process("./little")

for i in range(20):    
    b.recv().decode("utf-8")
    b.sendline('1')
    b.recvline().decode("utf-8")

b.sendline('3')
b.recv().decode("utf-8")
print(b.recvuntil('}').decode("utf-8"))
b.close()
```

![](/assets/img/ccc/05.png)

