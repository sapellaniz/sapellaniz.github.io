---
title: BKDR RILER
excerpt: "Hace unos días, por el grupo de Telegram de nuestro equipo de CTF GRAIL TEAM, S nos propuso analizar un malware que había obtenido de un repositorio de samples. Esu23 y yo, que también estamos bastante interesados en el análisis de malware, aceptamos su propuesta sin pensarlo. En esta entrada os contaremos cómo fué nuestra aventura analizando esta muestra."
date: 2021-02-21
categories: [Researching, Malware]
tags: [Researching, Malware]
---

> Hace unos días, por el grupo de Telegram de nuestro equipo de CTF GRAIL TEAM, S nos propuso analizar un malware que había obtenido de un repositorio de samples. Esu23 y yo, que también estamos bastante interesados en el análisis de malware, aceptamos su propuesta sin pensarlo. En esta entrada os contaremos cómo fué nuestra aventura analizando esta muestra.

---

# Descripción del laboratorio

Para analizar esta muestra hemos preparado un laboratorio con dos máquinas virtuales con los siguientes sistemas operativos y herramientas:

- Remnux:
  - inetsim
  - pwntools
- Windows 10:
  - IDAFreeware
  - OllyDBG
  - PEStudio

# Engañando al malware

La muestra es una dll llamada utntweep.dll, por desgracia en el repositorio no se encontraba el loader pero podemos continuar sin él.

Comenzamos analizando la muestra con PEStudio, vemos que tiene una entropía de 3.133 por lo que descartamos que esté empacado, también vemos que tiene imports sospechosos pero no encontramos ninguna cadena sospechosa.

Desensamblamos la muestra con IDA, renombramos la primera subrutina que es llamada con el nombre "Function_Start" y comenzamos a analizarla. Tiene una llamada a la función GetModuleFileNameA, si cargamos la dll con Olly y ponemos un breakpoint después de esta llamada, vemos que la dll ha detectado que ha sido "inyectada" en LOADDLL.EXE de Olly.

![](/assets/img/bkdr_riller/01.png)

Tambien vemos que inmediatamente después comprueba si ha sido inyectado en un proceso creado por alguno de los siguienes ejecutables: explorer.exe, outlook.exe, msimn.exe, netscp.exe, yahoomessenger.exe, msnmsgr.exe, opera.exe, firefox.exe, safari.exe o svchost.exe. Si es así, fija a True una variable booleana. Al terminar estas comprobaciones, comprueba el valor de la variable, si es False, termina su ejecución. Esto nos hace pensar que muy probablemente el vector de ataque fuera una campaña de phising.

Para poder depurar la dll de forma cómoda, la parcheamos para que no realice esta comprobación:

![](/assets/img/bkdr_riller/02.png)

A la izquierda vemos la dll original en IDA, a la derecha en Olly vemos la dll con un salto parcheado antes de establecer la variable booleana a True.

# Inicio

Una vez realizada esa primera comprobación, el malware crea dos threads a los que hemos llamado "Thread_1" y "Thread_2".

![](/assets/img/bkdr_riller/03.png)

Por simplicidad, explicaremos primero el funcionamiento de "Thread_2" ya que está compuesto por una única subrutina:

![](/assets/img/bkdr_riller/04.png)

Simplemente incrementa un contador "Count_1" cada 6 segundos, si el contador llega a 9 (después de 54 segundos), cierra el socket con el C2. Cada vez que el malware recibe un comando del C2, reestablece a 0 este contador, como veremos más adelante.

# Thread 1

La subrutina "Thread_1" se encarga básicamente de comunicarse con el C2 mediante la subrutina que hemos llamado "Function_C2_Comunication". También trata de reconectarse cada 13 segundos una vez perdida la conexión.

![](/assets/img/bkdr_riller/05.png)

# C2 Comunication

Esta es la subrutina más interesante y extensa, se encarga de comunicarse con el C2, recibiendo instrucciones y devolviendo resultados cuando es necesario.

Nada mas comenzar, llama a una subrutina que hemos renombrado como "Function_Get_PC_Data", hemos elegido este nombre porque guarda en una posición de memoria distintos datos de la máquina de la víctima, con el siguiente formato:

```
NAME: DESKTOP-N5KG583	VER: Stealth 4.0	MARK: tibpar	OS: nt 6.2	L_IP: 169.254.218.101	ID: NoID
```

Por último guarda las dos siguientes cadenas en una posición de memoria cada una: "EHL:G@e=RG:FB<=GLe\<HeND" y "mmll".

Inmediatamente después de llamar a "Function_Get_PC_Data", "Function_C2_Comunication" llama dos veces a una subrutina que hemos llamado "Function_Decrypt_String" pasando como argumento las cadenas que acabamos de ver. Hemos llamado así a esta subrutina porque aplicando ROT39 a cada cadena, las transforma en "losang.dynamicdns.co.uk" y "6655" respectivamente:

![](/assets/img/bkdr_riller/06.png)

Ya tenemos la dirección y el puerto por el que escucha el C2.

Después, mediante una subrutina que hemos llamado "Function_C2_Connect", trata de conectarse al C2. Primero intenta obtener su IP con la función "gethostbyname" y después con "htons", "ioctlsocket" y "connect" trata de conectarse.

Si no lo consigue retorna a "Thread_1" para volver a intentar conectarse a los 13 segundos. Si consigue conectarse, establece "Count_1" a 0 y llama a una subrutina que hemos llamado "Function_Recv_From_Socket", que lo único que hace es tratar de leer 1024 bytes del socket.

Si no recibe nada, retorna a "Thread_1". Si recive algun byte, lo guarda en una posición de memoria que va comparando con las siguientes cadenas: "WAKE", "DOWN", "FILE", "LONG", "DISK", "MOON", "ATTR", "KILL", "NAME", "LIKE", "SEEK", "READ", "DEAD", "KEEP" y "DONE".

Ya tenemos los comandos que puede recibir del C2. Llegados a este punto, metemos la máquina virtual con remnux en la misma red interna, levantamos un servidor DNS señuelo con la herramienta inetsim para que resuelva todas las consultas con su propia IP y configuramos el servidor DNS del Windows 10 con la IP de la máquina con remnux. Así podremos poner el netcat a la escucha y comunicarnos con el C2.

Aparentemente todo funciona correctamente pero cuando probamos ejecutar comandos que llaman a la función "FindFirstFileA" no se ejecutan correctamente y nos devuelven algún código de error.

En la documentación de Microsoft sobre esta función encontramos lo siguiente: "This parameter should not be NULL, an invalid string (for example, an empty string or **a string that is missing the terminating null character**), or end in a trailing backslash (\)."

Con un breakpoint en la llamada a "FindFirstFileA" examinamos el filename que se le está pasando como primer argumento y vemos lo siguiente:

![](/assets/img/bkdr_riller/07.png)

Nos damos cuenta que se le ha añadido 0x0A (salto de línea) a la ruta especificada en el comando, por lo que no está encontrando ningún archivo con ese nombre nunca. Para solucionar este problema, desarrollamos una interfaz en python con la libreria pwntools:

**c2.py**

```python
#!/usr/bin/python3

from pwn import *

def main():
    while True:
        l = listen(6655)
        l.wait_for_connection()

        while True:
            cmd = input("> ")
    
            # Empty command
            if(len(cmd[:-1]) == 0):
                continue
            
            try:
                l.send(cmd[:-1])
            except:
                log.info("Socket closed, reconnecting ...")
                break

            # WAKE returns nothing
            if(cmd[:-1] != "WAKE"):
                print(l.recv().decode("utf-8"))

if __name__ == '__main__':
    main()


```

Ya podemos comunicarnos con el malware de forma cómoda:

![](/assets/img/bkdr_riller/08.png)

Con esto podemos reversear los comandos facilmente. El funcionamiento de cada uno está detallado a continuación junto a los códigos de error:

**COMANDOS**

```
WAKE = Reinicia el idle time 
DOWN = Muestra el tamaño de un fichero
FILE = Modo de uso: FILE lineas archivo ; lineas = número de lineas a escribir en formato de 5 dígitos. ej: 00001
LONG = Carga un fichero en memoria y lo borra 
DISK = Comprueba si existe un fichero en el disco
MOON = Numera todas las unidades de disco del sistema
ATTR = Pone el atributo NORMAL al fichero pasado como argumento
KILL = Borra fichero
NAME = Imprime información de la víctima
LIKE = Reverse shell
SEEK = Lee un fichero cargado con LONG, a partir del índice que se le pase como argumento.
READ = Lee un fichero cargado con LONG
DEAD = Cierra la conexión 
KEEP = Fecha de modificación de un archivo
DONE = Ejecuta el comando que se le pase como argumento sin mostrar la salida
```

**CODIGOS DE ERROR**

```
00 = Comando exitoso
02 = Command not found
10 = ATTR no encuentra fichero
11 = No se puede borrar un fichero que no existe
12 = DONE siempre devuelve 12
```

