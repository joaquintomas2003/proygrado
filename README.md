# Proyecto de Grado

## Como usar Dissector
- Correr el script `utils/reload_dissector.sh`
- En Wireshark hacer "Reload Lua Plugins" (`Shift + Cmd + L` en mac)

Hacer eso la primera vez y cuando hayan cambios en el dissector

## Scripts para stack de Elastic + Filebeat

Este proyecto incluye dos scripts para manejar la infraestructura de monitoreo:

- `bin/ensure_stack`: chequea que **Elasticsearch**, **Kibana** y **Filebeat** estén corriendo en el host.  
  Si alguno no está en ejecución, lo inicia automáticamente.
- `bin/setup_filebeat`: configura Filebeat para que tracee los logs de **Netronome**.

## Cómo acceder a Kibana

Para visualizar Elasticsearch/Kibana, es necesario conectarse al host con un túnel SSH:

```bash
ssh -J nombre.apellido@lulu.fing.edu.uy -L 5601:localhost:5601 host@ip
```

Luego, abrir en el navegador el siguiente enlace:

```
http://localhost:5601
```

## ⚠️ Advertencia

El host debe contar con **Elasticsearch**, **Kibana** y **Filebeat** instalados.  
Estos pueden instalarse utilizando `apt-get` y siguiendo las instrucciones en sus sitios oficiales.
