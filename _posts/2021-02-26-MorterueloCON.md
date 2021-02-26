---
layout: single
title: MorterueloCON
excerpt: "Writeups de un par de pruebas de la MorterueloCON2021."
date: 2021-02-26
classes: wide
author: sapellaniz
categories:
  - RE
  - Forensics
tags:
  - radare2
  - wireshark
  - RE
  - Forensics
---
# Super-secret container (Reversing)

> Has encontrado un pendrive con el símbolo del Consorcio Internacional Aeroespacial. Sólo contiene un fichero y parece contenter un gran secreto... ¿Serás capaz de desvelarlo?
---

### Analizando el binario

Lo primero que hago es comprobar de qué tipo de archivo se trata el de este reto:

```
$ file SuperSecretContainer
SuperSecretContainer: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f21ee021f151ad4552a076a5e55144e104c3f9ed, for GNU/Linux 3.2.0, not stripped
```

Se trata de un ELF de 64 bits, linkado dinámicamente y sin estripear, compruebo las strings y las librerias que son llamadas:

```
$ strings SuperSecretContainer
...
You got it!! =>
Not the expected numbers. Try again!
Something must be wrong...
...
$ ltrace ./SuperSecretContainer
.▄▄ · ▄• ▄▌ ▄▄▄·▄▄▄ .▄▄▄      .▄▄ · ▄▄▄ . ▄▄· ▄▄▄  ▄▄▄ .▄▄▄▄▄
▐█ ▀. █▪██▌▐█ ▄█▀▄.▀·▀▄ █·    ▐█ ▀. ▀▄.▀·▐█ ▌▪▀▄ █·▀▄.▀·•██
▄▀▀▀█▄█▌▐█▌ ██▀·▐▀▀▪▄▐▀▀▄     ▄▀▀▀█▄▐▀▀▪▄██ ▄▄▐▀▀▄ ▐▀▀▪▄ ▐█.▪
▐█▄▪▐█▐█▄█▌▐█▪·•▐█▄▄▌▐█•█▌    ▐█▄▪▐█▐█▄▄▌▐███▌▐█•█▌▐█▄▄▌ ▐█▌·
 ▀▀▀▀  ▀▀▀ .▀    ▀▀▀ .▀  ▀     ▀▀▀▀  ▀▀▀ ·▀▀▀ .▀  ▀ ▀▀▀  ▀▀▀
 ▄▄·        ▐ ▄ ▄▄▄▄▄ ▄▄▄· ▪   ▐ ▄ ▄▄▄ .▄▄▄
▐█ ▌▪▪     •█▌▐█•██  ▐█ ▀█ ██ •█▌▐█▀▄.▀·▀▄ █·
██ ▄▄ ▄█▀▄ ▐█▐▐▌ ▐█.▪▄█▀▀█ ▐█·▐█▐▐▌▐▀▀▪▄▐▀▀▄
▐███▌▐█▌.▐▌██▐█▌ ▐█▌·▐█ ▪▐▌▐█▌██▐█▌▐█▄▄▌▐█•█▌
·▀▀▀  ▀█▄▀▪▀▀ █▪ ▀▀▀  ▀  ▀ ▀▀▀▀▀ █▪ ▀▀▀ .▀  ▀
                                           MorterueloCON 2021
Are you able to beat the lock?
Enter secure key: flag
That's not the right key!!
+++ exited (status 0) +++
```

Solamente encuentro unas cadenas interesantes, lo siguiente que hago es analizarlo con radare2:

```
$ r2 -AAA SuperSecretContainer
...
[0x000012a0]> /w You got it!!
...
0x00003009 hit4_0 .You got it!! => Not t.
[0x000012a0]> axt @0x00003009
sym.magic__ 0x1934 [DATA] lea rsi, str.You_got_it_____
```

### Cambiando el comportamiento

Después de estar un rato jugando con el binario y gdb, veo que en la subrutina main, para que no se termine la ejecución de forma prematura, la cadena que le pase al binario tiene que tener el formato "Morteruelo2021{\*}".

Dándole vueltas a como seguir se me ocurre probar a saltar a la función magic directamente, ya que tiene varios strcat y me parece que está componiendo la flag antes de imprimirla:

```

gef➤  entry-break

gef➤  b *0x555555555e21		# <- Breakpoint en el ret de main

gef➤  run

# Introduzco una cadena aleatoria y el programa choca con el breakpoint

gef➤  set $rip = 0x555555555861	# <- Cambiar RIP para que apunte al comienzo de magic

gef➤  c

Continuing.
You got it!! => Morteruelo2021{x0r_15_n07_4lw4y5_53cur3}
[Inferior 1 (process 18736) exited with code 0100]
```

---
# Ping the flag (Forensics)

> "Nuestros expertos en comunicaciones han detectado un pequeño y extraño tráfico desde un servidor crítico a otro equipo de la intranet. Sospechan que puede ser un intento de burlar la seguridad perimetral y enviar información de alto nivel hacia el exterior, pero no han logrado demostrarlo. ¿puedes ayudarles con tus habilidades de hacker?
---

### Analizando el pcap

Para este reto nos entregan el archivo "capture.pcap", lo abro con Wireshark y lo primero que me llama la atención es que solamente tiene pings capturados.

Analizando los pings enviados, no tardo en darme cuenta que todos los mensajes son iguales excepto los 2-3 ultimos bytes que si se pasan a ASCII son números que, a su vez, se pueden interpretar como ASCII en decimal:

![](/assets/images/morteruelo/01.png)

### Automatizando la solución

A partir de este punto podría ir descifrando paquete a paquete la letra oculta de la flag, pero creo que lo entretenido es obtener la flag con un solo comando o un script que automatice esta tarea. Tras un buen rato jugando con expresones regulares y leyendo el manual de Tshark, doy con la clave:

```
$ echo $(for y in $(for x in $(tshark -T pdml -r capture.pcap | grep "Data: " | cut -d '"' -f 4 | cut -d " " -f 2 | sed 's/../ 0x&/' | tr -d "\n"); do echo -n $x | xxd -r ;echo ; done); do printf \\$(printf "%o" $y);done;)  | grep -o . | sed -n '1~2 p' | tr -d "\n"
Morteruelo2021{P1n91n9_d4t4_15_4w350m3}%
```



