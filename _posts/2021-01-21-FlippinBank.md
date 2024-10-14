---
title: HTB - FlippinBank
excerpt: "The Bank of the World is under attack. Hackers found a way in and locked the admins out. However, the netcat authentication by the intruders is not perfectly secure. Could you help the admins log in?"
date: 2021-01-21
categories: [HTB, Crypto]
tags: [HTB, Crypto]
---
`Crypto`
>   The Bank of the World is under attack. Hackers found a way in and locked the admins out. However, the netcat authentication by the intruders is not perfectly secure. Could you help the admins log in?

---

# Analizar el código

El primer paso es analizar el código del archivo "app.py" que nos adjuntan en el zip:

**app.py**

```python
import socketserver 
import socket, os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes
from binascii import unhexlify
from secret import FLAG


wlcm_msg ='########################################################################\n'+\
		  '#                  Welcome to the Bank of the World                    #\n'+\
		  '#             All connections are monitored and recorded               #\n'+\
		  '#      Disconnect IMMEDIATELY if you are not an authorized user!       #\n'+\
		  '########################################################################\n'


key = get_random_bytes(16)
iv = get_random_bytes(16)


def encrypt_data(data):
	padded = pad(data.encode(),16,style='pkcs7')
	cipher = AES.new(key, AES.MODE_CBC,iv)
	enc = cipher.encrypt(padded)
	return enc.hex()

def decrypt_data(encryptedParams):
	cipher = AES.new(key, AES.MODE_CBC,iv)
	paddedParams = cipher.decrypt( unhexlify(encryptedParams))
	print(paddedParams)
	if b'admin&password=g0ld3n_b0y' in unpad(paddedParams,16,style='pkcs7'):
		return 1
	else:
		return 0

def send_msg(s, msg):
	enc = msg.encode()
	s.send(enc)

def main(s):
	send_msg(s, 'username: ')
	user = s.recv(4096).decode().strip()

	send_msg(s, user +"'s password: " )
	passwd = s.recv(4096).decode().strip()
	
	send_msg(s, wlcm_msg)

	msg = 'logged_username=' + user +'&password=' + passwd

	try:
		assert('admin&password=g0ld3n_b0y' not in msg)
	except AssertionError:
		send_msg(s, 'You cannot login as an admin from an external IP.\nYour activity has been logged. Goodbye!\n')
		raise

	msg = 'logged_username=' + user +'&password=' + passwd
	send_msg(s, "Leaked ciphertext: " + encrypt_data(msg)+'\n')
	send_msg(s,"enter ciphertext: ")

	enc_msg = s.recv(4096).decode().strip()
	
	try:
		check = decrypt_data(enc_msg)
	except Exception as e:
		send_msg(s, str(e) + '\n')
		s.close()

	if check:
		send_msg(s, 'Logged in successfully!\nYour flag is: '+ FLAG)
		s.close()
	else:
		send_msg(s, 'Please try again.')
		s.close()


class TaskHandler(socketserver.BaseRequestHandler):
	def handle(self):
		main(self.request)

if __name__ == '__main__':
	socketserver.ThreadingTCPServer.allow_reuse_address = True
	server = socketserver.ThreadingTCPServer(('0.0.0.0', 1337), TaskHandler)
	server.serve_forever()
```

Parece el código que está corriendo en el servidor. Nos pide un username y una password, en caso de ser "admin:g0ld3n_b0y" nos salta la excepción de la línea 53. Luego escribe un mensaje con las credenciales que hemos proporcionado, lo cifra usando el algoritmo AES-CBC y lo imprime. Por último nos pide un texto cifrado que al descifrarlo con el mismo algoritmo y la misma clave sea "admin&password=g0ld3n_b0y" para imprimir la flag.

Podemos ver en el código, por la longitod de "key" e "iv" que los bloques serán de 16 bytes, si introducimos las credenciales que hacen saltar la excepción, los bloques serían los siguientes:
* B1: "logged_username="
* B2: "admin&password=g"
* B3: "0ld3n_b0y·······"

Esto hace que el primer bloque (16 primeros bytes de "Leaked ciphertext") siempre sea igual, ya que "key" e "iv" son aleatorios pero constantes.  

# Encontrar la vulnerabilidad

Rapidamente se puede ver que se trata de un [bit-flipping-attack](https://resources.infosecinstitute.com/topic/cbc-byte-flipping-attack-101-approach/). debemos modificar un byte del primer bloque cifrado para que al descifrar el mensaje, el segundo bloque contenga "admin&password=g". El primer bloque quedará completamente modificado pero no nos importa ya que solamente se comprueba que el mensaje descifrado contenga la siguiente cadena "admin&password=g0ld3n_b0y" que se encuentra repartida entre el segundo y tercer bloque.

# Escribir el exploit

Una vez descubierta la vulnerabilidad podemos escribir un exploit que automatice el ataque:

**exploit.py**

```python3
#!/usr/bin/python3
from pwn import *

msg = "logged_username=admin&password=g0ld3n_b0y"
username = "bdmin"
password = "g0ld3n_b0y"

p = remote("209.97.138.240", 30977)

p.recvuntil("username: ")
p.send(username)

p.recvuntil("password: ")
p.send(password)

p.recvuntil("ciphertext: ")
c1 = p.recvuntil("\n")

# Extraer primer byte del primer bloque
a = int(c1[:2].decode("utf-8"), 16)

# Calcular el nuevo byte
b = hex(a ^ ord('b') ^ ord('a'))
b = str(int(b, 16)).rjust(2, '0')
b = hex(int(b))[2:]

# Reemplazar el primer byte del primer bloque
c2 = b+c1.decode("utf-8")[2:]

# Enviar el texto cifrado y obtener la cadena
p.send(c2)
p.recvuntil('\n')
print(p.recv())
p.close()
```
