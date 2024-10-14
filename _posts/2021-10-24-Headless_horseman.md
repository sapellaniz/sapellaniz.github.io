---
title: BuckeyeCTF2021 - The Legend of the Headless Horseman
excerpt: "BKY - The Legend of the Headless Horseman"
date: 2021-06-12
categories: [CTF, RE]
tags: [CTF, BuckeyeCTF2021, RE]
---
`Reversing`
>  The Legend of the Headless Horseman
> A mysterious figure has been terrorizing the village of Sleepy Hollow. He rides a massive horse, swings a mighty scythe and has been collecting heads from any who draw near. A group of locals, Ichabod Crane, Katrina Van Tassel, and Abraham "Brom Bones" Van Brunt have been working to discover the secret behind this mysterious menace, but just as they were on the verge of putting the pieces together, the Headless Horseman struck! All that are left of the heroes are some unidentifiable bodies with no heads!
> Can you help put our heroes back together, and figure out what secrets they uncovered? You'll first need to bargain with the horseman... bring some pumpkins with you.. a LOT of pumpkins.
---

# Dealing with the headless horseman

Para este se entrega un zip llamado "headless_horseman.zip", que contiene el binario headless_horseman y la carpeta "body_bag" con los archivos "bloated_body", "decomposing_body" y "rotting_body", de formato desconocido.

Al ejecutar el binario, se imprimen los siguientes mensajes:

```
You see a dark figure looming in the darkness
As you approach he raises his hand to stop you
The figure holds up a bloody sack as if offering the contents to you
He holds out his other hand, as if expecting some kind of offering
you look back in your cart and scan over the pumpkins you brought.. will it be enough?
how many pumpkins did you bring with you this time?
```

Entonces espera recibir un entero por stdin, si no se introduce la cifra esacta, se imprimen los siguientes mensajes:

```
The figure pulls a head off the saddle and holds it over the cart and you hear it mumble as it inspects your offering
the figure turns to you and draws his sword... time to leave! make sure to bring the right number of pumpkins next time!
```

Si se analiza el binario con ghidra, puede verse que la función "main" solamente contiene las siguientes instrucciones:

```
print_intro();
uVar1 = offer_pumpkins();
count_offering(uVar1);
return 0;
```

La función "offer_pumpkins()" básicamente lee de stdin un entero y el resultado se guarda en una variable que se pasa como argumento a la otra función "count_offering();", esta última funcion contiene las siguientes instrucciones:

![](/assets/img/headless_horseman/01.png)

Si el entero que lee el binario cumple con las condiciones de las funciones "first_count()" y "second_count()", llamará a la función "dump_heads()".

### first_count()
```
return param_1 >> 0x10 == 0xdead;
```

### second_count()
```
return param_1 == 0xface;
```

El caballero sin cabeza quería exactamente 0xdeadface calabazas (3735943886 en decimal). Si le damos este numero de calabazas, su respuesta será diferente:

```
The figure pulls a head off the saddle and holds it over the cart and you hear it mumble as it inspects your offering
You hear a grunt of approval but the mumbling continues
The figure turns to you and nods, pulling out his bag of heads, dumping them on the ground in front of you
A quick count indicates more heads than you were expecting, he is quite the collector!
well, you seem have gotten what you came for..time to start stitching
As you pick up the first head you begin to wonder which body it might belong to, and how on earth you might go about reviving these poor souls...
maybe you can use the fabled Quick and Efficient Murder Un-Doer(QEMU for short)
```

Despues de esto, en la carpeta actual se crean los siguientes archivos "dessicated_head", "fetid_head", "moldy_head", "putrid_head", "shrunken_head", "swollen_head". Se puede comprobar que tipo de archivos son con el siguiente comando:

```
$ file *_head
dessicated_head: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), can't read elf program headers at 52, missing section headers at 526052
fetid_head:      ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)
moldy_head:      ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), can't read elf program headers at 52, missing section headers at 611964
putrid_head:     ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)
shrunken_head:   ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV)
swollen_head:    ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)
```

Pero ninguno se ejecuta correctamente, solamente tienen 64 bytes. Esto es así porque son las cabeceras de los binarios que hay en la carpeta "body_bag".

Tenemos 6 cabezas pero solo queríamos 3! Tendremos que ir probando todas las combinaciones hasta ensamblar los cuerpos de Ichabod Crane, Katrina Van Tassel y Abraham "Brom Bones" Van Brunt con sus respectivas cabezas... Puede que algo de superglu nos venga bien...


# Bringing the parts together

Se puede escribir un script para automatizar esta tarea:

**supergly.py**
```python
#!/usr/bin/python3

bodies = ["bloated_body", "decomposing_body", "rotting_body"]
heads = ["dessicated_head", "fetid_head", "moldy_head", "putrid_head", "shrunken_head", "swollen_head"]

f = open("franky.bin", "wb")

part = open(heads[0], "rb")
f.write(part.read())
part.close

part = open("body_bag/"+bodies[0], "rb")
f.write(part.read())
part.close

f.close()
```

### Abraham Brom Bones

Probando las posibles combinaciones de cabeceras-cuerpo, se llega a que la combinación "rotting_body" + "shrunken_head" forma un ELF que se puede ejecutar en x86_64. Cuando se ejecuta imprime los siguientes mensajes:

```
Brom shakes himself off as he stands up
'Well that was certainly an experience' he says, 'thanks for the help!'
You see him shake his head.. 'though i'm not sure you screwed me back perfectly.. something feels a bit off'
'think you have any medicine to help straighten out my thoughts?'
```

Entonces el binario lee una cadena por stdin, si se le pasa una cadena diferente a la que espera imprime los siguientes mensajes:

```
Brom's eyes glaze over for a second and he writes down this number: 0xdeadbeef
Brom shakes himself off again
'Nope, that didn't seem to do it.. could you try again? REALLY cram it down my throat, I want to be overflowing with medicine!'
```

Como no somos médicos, decidimos practicarle un bypass, lo ejecutamos con gdb, ponemos un breakpoint en el salto condicional que realiza la comprobación de la medicina, y cambiamos la flag ZERO para que no lo tome (el binario está compilado con PIE, es decir que el código se carga en una posición de memoria aleatoria, entonces con gdb tendremos que poner un breakpoint en el entrypoint y calcular la diferencia entre la dirección estática y la dirección al cargar el programa en memoria).

```
$ r2 -AAA franky.bin
[0x00001110]> s main
[0x00001416]> pdf
...
0x0000142a      e8a9feffff     call sym.brom
...
[0x00001416]> s sym.brom
[0x000012d8]> pdf
...
0x0000138f      754a           jne 0x13db
...
[0x000012d8]> q

$ gdb franky.bin
gef➤  entry-break
gef➤  b* 0x5655638f
gef➤  c
...
333
...
gef➤  flags
[zero carry parity adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
gef➤  flags +ZERO
[ZERO carry parity adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
gef➤  c
Continuing.
'WOW! I think that did the trick, it's all coming back to me now'
'here is my piece to this creepy puzzle, though I have no idea what it means..'
pumpkin_pie}
```

Hemos condeguido salvar a Brom y a cambio nos da una parte de la flag... Ahora toca salvar a sus compañeros!

### Katrina Van Tassel

En este punto se puede descartar el cuerpo y cabezera usados en la parte anterior del reto.

Si se pasa la cabezera de ARM "dessicated_head", los dos cuerpos restantes y el script "superglu.py", se puede ver rápidamente que ensamblándolo con el cuerpo "decomposing_body" forman un binario perfectamente ejecutable. Cuando se ejecuta imprime los siguientes mensajes:

```
Katrina blinks awake seeming a bit shocked ot be waking up again
'Oh hello there just before the lights went out I was working with Ichabod and Brom to get rid of that pesky horseman for good'
'Drat it looks like I encrypted my portion but I cant seem to remember what I used'
'can you help me out  I was never very creative with these things  maybe try the street I grew up on  or my Home Town'
```

Entonces el binario lee por stdin una cadena, y después imprime los siguientes mensajes:

```
'You really think its that?'
'Well ill give that a shot  does this look right'
```

Y luego imprime una cadena de caracteres. Con ghidra puede verse que está imprimiendo la cadena que se pasa por stdin tras hacer un XOR con una cadena de 13 bytes hardcodeada en el binario:

```
iStack116 = 0;
while (iStack116 < 0xe) {
  abStack112[iStack116] = (&encrpyted_words)[iStack116] ^ abStack112[iStack116];
  iStack116 = iStack116 + 1;
}
```

Esta vez no podemos realizar un bypass y no tenemos tiempo suficiente para realizar un ataque de fuerza bruta... Después de darle vueltas a la información que nos dió Katrina Van Tassel, probamos a usar como contraseña el pueblo en el que vive "Sleepy Hollow"... Correcto! Entonces obtenemos otro fragmento de la flag: "really_loves_"

### Ichabod Crane

__"En este punto apostamos por que la cabecera restante era la de MIPS ya que es una arquitectura común en retos de reversing, la ensamblamos con el cuerpo restante y sacamos la porción de flag, que estaba hardcodeada en base64, sin ejecutar el binario porque no teníamos una máquina de esta arquitectura a mano, pero a continuación simularemos la via intencionada."__

En este punto solamente queda un cuerpo por ensamblar con su correspondiente cabecera. Si se ensambla el cuerpo ("bloated_body") con la cabecera de la arquitectura MIPS ("moldy_head") y se mueve a una máquina de esta arquitectura, se puede ejecutar perfectamente. Cuando se ejecuta, imprime los siguientes mensajes:

```
Ichabod Crane gasps as life returns to his body
He begins looking around frantically
He appears to not find what he is looking for and collapses back to the ground
```

Si se analiza el código con radare2, puede verse que en el main solamente llama a la función "ichabod()", dentro de esta función solamente hay una dos llamadas, la primera es a una función con el nombre "check_surroundings()", en esta función se lee el valor de la variable de entorno "ICHABODS_HORSE" y se compara con la cadena "GUNPOWDER". Si las dos cadenas son iguales, entonces se llama a la segunda función "sym.print_incantation()". En esta última función se decodifica una cadena en base64 que resulta ser la porción de flag restante.

Buscamos el caballo de Ichabod Crane, lo traemos y volvemos a despertarle, entonces su reacción es diferente:

```
'ah, my trusty steed GUNPOWDER is here, all is well' he says, pulling something out of a saddlebag
'Here, I don't have the whole secret, but here is the piece I was able to find'
flag{the_horseman_just_
```
