---
title: HTB - xorxorxor
excerpt: "Who needs AES when you have XOR?"
date: 2021-01-20
categories: [HTB, Crypto]
tags: [HTB, Crypto]
---
`Crypto`
>  Who needs AES when you have XOR? 
---

# Analizar el código

El primer paso es analizar el código del archivo que nos adjuntan en el zip:

**challenge.py**

```python
#!/usr/bin/python3
import os
flag = open('flag.txt', 'r').read().strip().encode()

class XOR:
    def __init__(self):
        self.key = os.urandom(4)
    def encrypt(self, data: bytes) -> bytes:
        xored = b''
        for i in range(len(data)):
            xored += bytes([data[i] ^ self.key[i % len(self.key)]])
        return xored
    def decrypt(self, data: bytes) -> bytes:

        return self.encrypt(data)

def main():
    global flag
    crypto = XOR()
    print ('Flag:', crypto.encrypt(flag).hex())

if __name__ == '__main__':
    main()
```


El script parece ser el que ha generado el texto cifrado en el fichero "output.txt" haciendo un XOR byte a byte a la flag con una clave desconocida generada aleatoreamente de 4 bytes.

Hay 4.294.967.296 posibles combinaciones de 4 bytes, podríamos hacer fuerza bruta y sacar la clave pero hay un método mucho más rápido y sencillo: como conocemos el formato de la flag "HTB{...}", podemos sacar la clave con la que se hizo el XOR a la flag, volviendo a hacer XOR al texto cifrado con la clave de 4 bytes "HTB{", ya que si "A ^ B = C" => "C ^ A = B".

Una vez obtenida la clave, basta con aplicársela al texto cifrado para obtener la flag gracias a la propiedad de XOR que acabamos de ver.

# Escribir el solver

Se puede resolver con un sencillo script:

**exploit.py**

```python
#!/usr/bin/python3

# Guardar la flag codificada
enc = open('output.txt', 'r').read().strip().encode()
enc = enc.split()[1]

# Obtener la clave real
key = [0x48, 0x54, 0x42, 0x7b] # "HTB{"
rkey = [0]*4
for i in range(0,4):
    rkey[i] = int(enc[i*2:i*2+2].decode("utf-8"), 16) ^ key[i]

# Obtener la flag
flag = ""
for i in range(0,31):
    flag += chr(rkey[i%4] ^ int(enc[i*2:i*2+2].decode("utf-8"), 16))

print(flag)
```


