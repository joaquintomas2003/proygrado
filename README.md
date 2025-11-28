# Proyecto de Grado: Programabilidad de Red aplicada al Monitoreo mediante In-band Network Telemetry

## Descripción General
Este repositorio contiene el código fuente desarrollado para el Proyecto de Grado titulado "Programabilidad de Red aplicada al Monitoreo mediante In-band Network Telemetry".
El proyecto se enfoca en la implementación de un sistema de monitoreo de red utilizando [In-band Network Telemetry (INT)](https://p4.org/wp-content/uploads/sites/53/p4-spec/docs/INT_v2_1.pdf) en dispositivos de red programables.
En particular, se implementa: 
- Un INT Sink en SmartNICs Netronome Agilio CX 2x10GbE conectado a una capa de almacenamiento y visualización de datos utilizando ELK (Elasticsearch, Kibana y Filebeat).
- Una prueba de concepto de INT Transit Hop en bmv2.

## Estructura del Repositorio
- `doc/`: documentación del proyecto.
- `src/`: código fuente del proyecto.

Dentro de `src/`, la estructura es la siguiente:
- `bin/`: scripts ejecutables para diversas tareas (iniciar y/o configurar servicios, compilar y cargar programas en SmartNICs, etc).
- `dissectors/`: dissector de Wireshark para paquetes INT.
- `elastic/`: configuración de Elasticsearch y Filebeat.
- `evaluation/`: scripts y herramientas para la evaluación del rendimiento del sistema.
- `host/`: programas que se ejecutan en el host que interactúa con las SmartNICs: lectura de ring buffers, spooling de metadatos leídos.
- `sink/`: programa p4 y funciones en C para el INT Sink en las SmartNICs Netronome.
- `traffic_generator/`: generador de tráfico para pruebas.
- `transit_hop/`: programa p4 para el INT Transit Hop en bmv2.
- `utils/`: utilidades varias (regarcar dissector).
- `wire/`: programa p4 básico para pruebas de baseline.

## Uso 
Para utilizar la plataforma se deben satisfacer los requisitos de hardware y software detallados en la sección de Requisitos.

### Como usar Sink
- Compilar el programa P4 del Sink:
```bash
cd sink
../bin/p4 build
```
- Cargar el programa P4 en la SmartNIC:
```bash
../bin/p4 design-load
```

- Correr el programa en el host para leer los metadatos INT:
```bash
cd ../host
sudo make restart
```

### Como enviar tráfico con INT al Sink

1. **Generar la traza**: Si se desea generar una traza (`.pcap`) de tráfico con INT:
   - Moverse al directorio del generador de tráfico:
     ```bash
     cd traffic_generator
     ```
   - Si se desea ajustar la configuración del tráfico, editar el archivo `config.yaml`.
   - Correr el generador de tráfico:
     ```bash
     python3 int_injector.py
     ```
     Ese script insertará metadatos INT en los paquetes de la traza original indicada en `config.yaml`.

2. **Enviar la traza al Sink**: Para enviar la traza generada al Sink, se puede utilizar `tcpreplay`:
   ```bash
   sudo tcpreplay -i <INTERFAZ_DE_LA_SMARTNIC> --topspeed generated_int.pcap
    ```
    O usar Moongen (se debe asociar la interfaz virtual a DPDK primero, así como configurar las hugepages):
    ```bash
    ./bin/dpdk_bind_if vf0_0
    sudo ~/MoonGen/setup-hugetlbfs.sh
    sudo MoonGen evaluation/replay_pcap.lua 0 -n 1 traffic-generator/generated_int.pcap
    ```

### Como usar stack ELK
**Scripts para stack de Elastic + Filebeat**

Este proyecto incluye dos scripts para manejar la infraestructura de monitoreo:

- `bin/ensure_stack`: chequea que **Elasticsearch**, **Kibana** y **Filebeat** estén corriendo en el host.  
  Si alguno no está en ejecución, lo inicia automáticamente.
- `bin/setup_filebeat`: configura Filebeat para que tracee los logs de **Netronome**.

**Cómo acceder a Kibana**

Para visualizar Elasticsearch/Kibana, es necesario conectarse al host con un túnel SSH:

```bash
ssh -J nombre.apellido@lulu.fing.edu.uy -L 5601:localhost:5601 host@ip
```

Luego, abrir en el navegador el siguiente enlace:

```
http://localhost:5601
```

### Como usar Dissector
- Correr el script `utils/reload_dissector.sh`
- En Wireshark hacer "Reload Lua Plugins" (`Shift + Cmd + L` en mac)

Hacer eso la primera vez y cuando hayan cambios en el dissector

## Requisitos
Además de los requisitos de hardware como las SmartNICs Netronome Agilio CX 2x10GbE (no se experimentaron otras; podrían funcionar otras SmartNICs compatibles con P4), se necesitan las siguientes herramientas de software:
- Kernel de linux compatible con las SmartNICs de Netronome (en este trabajo se utilizó Unbuntu `18.04.6 LTS` con kernel `4.18.0-15-generic`)
- SDK de Netronome / NFP Drivers
- Soporte para hugepages (requerido para DPDK y MoonGen)
- DPDK
- MoonGen (requiere LuaJIT)
- Elasticsearch
- Kibana
- Filebeat
- Wireshark + tshark
- Python3 y bibliotecas asociadas (por ejemplo `scapy`)
