---
title: MorterueloCON
excerpt: "Writeups de un par de pruebas de la MorterueloCON2021."
date: 2021-02-26
categories: [CTF, RE, Forensics, Crypto]
tags: [CTF, MorterueloCon2021, RE, Forensics, Crypto]
---

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

![](/assets/img/morteruelo/01.png)

### Automatizando la solución

A partir de este punto podría ir descifrando paquete a paquete la letra oculta de la flag, pero creo que lo entretenido es obtener la flag con un solo comando o un script que automatice esta tarea. Tras un buen rato jugando con expresones regulares y leyendo el manual de Tshark, doy con la clave:

```
$ echo $(for y in $(for x in $(tshark -T pdml -r capture.pcap | grep "Data: " | cut -d '"' -f 4 | cut -d " " -f 2 | sed 's/../ 0x&/' | tr -d "\n"); do echo -n $x | xxd -r ;echo ; done); do printf \\$(printf "%o" $y);done;)  | grep -o . | sed -n '1~2 p' | tr -d "\n"
Morteruelo2021{P1n91n9_d4t4_15_4w350m3}%
```

---
# Basic (Crypto)

> "Simple"
---

### Resolviendo

La descripción del reto no engaña, nos entregan un .rar con un .txt con el siguiente contenido:

```
$ cat Basic.txt
109-111-114-116-101-114-117-101-108-111-50-48-50-49-123-99-114-49-112-116-48-95-98-52-115-49-99-125%
$ for x in $(cat Basic.txt | tr "-" "\n"); do printf \\$(printf "%o" $x); done
morteruelo2021{cr1pt0_b4s1c}%
```

---
# ¡Qué reverso! (Crypto)

> "El camino se hace paso a paso, pero dar un solo paso no es caminar. Sigue la senda, mi pequeño hacker."
---

### Resolviendo

Para este reto nos entregan un .zip con un .txt dentro con el siguiente contenido:

```
89504e470d0a1a0a0000000d4948445200000172000001720100000000c0
5f6ca40000028249444154789ced9b4d8ae3301085bf1a0bb294610e90a3
c8376bfa66f151728080b50cd8bc5948ca0f3d7fcd389e3694174196bfc5
834749a52ac5c4679ef1dba77070de79e79d77de79e77fc55b7d028c66c6
68a1ce0db97d1b36d4e3fcca7c92244d005122e96a3ad1a9fc48d233ff6a
3dceafcce71aa1366433c8017b9b963a6716b6d6e3fc3a7cf830132fc188
731008c8dbea71fee57c27c8079959c086ffafc7f915f828e904400e9074
3592e6f24d6aa3afabdff9dff2a39999f5409a00f241c569584afabcad1e
e757e2cbfefb58a48c5753d975e3d5203e1730bf9a7ee7ff866fc7dc80de
ed201b584cef7da792587bfebc5b9e7ab88d73d9667502ca4938b5578873
3d229fbe9a7ee7fff0147fd3d409e86e23d0a9543a2469aa450ef7776f3c
d5b77bfcc66a68cb9f9bb5eeef1ef95bfc02357ea9497492f47448727ff7
c73faecf0f013b51460f5baffbbb777eb44359a96d8012c4d2f9d00a1f9b
eb71fedf795a64ce3561565b955bd7a853dd933d7e77c83fda58b3aa9a35
b74ee1dd73f7777ffc9379f156668ecddffbabfbbb47fe69419ea075f5ef
a39a6ef9fabc4bbe151e738f110569ea4dc44bb03282fa611b3dceafcb3f
f4f7450eb31185a57340e351182c0639cc964e5be871fe157ca94596b3ee
d90ca2646fe7d08a1cd3c67a9c5f8b2ff1dbbabbdd5c6fe5b004c6be03f2
f719584cdbe871fe257c6d23800d3950fafb695aacc4f478f4fb1b3be7f3
ed86336043bc1ae3512ad7a1cbdca67a9c7f253f5a80342d564f4f67efef
ef94ffc9fdd8ab89dca3d13a310e40bd2ebb851ee7d7e59bbfb1de75d6d8
5f30e8664b5a8ca47bf6b5851ee7d7e56ff567a034045bfdaad52c6fd569
af5fed9037ff7fb7f3ce3befbcf3ce6fceff00b9b4c87db9e5432e000000
0049454e44ae426082
```

Para resolver este reto me sirvo de la herramienta online [CyberChef](https://gchq.github.io/CyberChef/):

![](/assets/img/morteruelo/02.png)

