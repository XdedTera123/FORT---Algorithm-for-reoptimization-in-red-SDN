
#!/usr/bin/env python3
# ETAPA 01 - ACTIVIDAD 01
# Definicion y despliegue de la topologia SDN.
# La fuente de configuracion es config/escenario.json.

import json
import os
from collections import deque
from pathlib import Path

from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel

BASE = Path(__file__).resolve().parents[1]
ARCHIVO_CONFIG = BASE / "config" / "escenario.json"


def cargar_configuracion():
    with ARCHIVO_CONFIG.open(encoding="utf-8") as archivo:
        config = json.load(archivo)

    switches = config["switches"]
    hosts = config["hosts"]
    enlaces = config["enlaces"]

    if not switches or not hosts or not enlaces:
        raise ValueError("La topologia esta incompleta.")

    if len(switches) != len(set(switches)):
        raise ValueError("Existen switches duplicados.")

    nombres_hosts = [h["nombre"] for h in hosts]
    ips_hosts = [h["ip"] for h in hosts]

    if len(nombres_hosts) != len(set(nombres_hosts)):
        raise ValueError("Existen hosts duplicados.")

    if len(ips_hosts) != len(set(ips_hosts)):
        raise ValueError("Existen direcciones IP duplicadas.")

    if set(switches) & set(nombres_hosts):
        raise ValueError("Un host y un switch comparten nombre.")

    vecinos = {sw: set() for sw in switches}
    enlaces_unicos = set()

    for a, b in enlaces:
        if a not in vecinos or b not in vecinos or a == b:
            raise ValueError(f"Enlace invalido: {a}-{b}")

        clave = frozenset((a, b))

        if clave in enlaces_unicos:
            raise ValueError(f"Enlace duplicado: {a}-{b}")

        enlaces_unicos.add(clave)
        vecinos[a].add(b)
        vecinos[b].add(a)

    for host in hosts:
        if host["switch"] not in vecinos:
            raise ValueError(
                f"Switch inexistente para {host['nombre']}"
            )

    visitados = set()
    pendientes = deque([switches[0]])

    while pendientes:
        actual = pendientes.popleft()

        if actual in visitados:
            continue

        visitados.add(actual)

        for vecino in vecinos[actual] - visitados:
            pendientes.append(vecino)

    if len(visitados) != len(switches):
        raise ValueError("La topologia no esta conectada.")

    if config.get("protocolo") != "OpenFlow13":
        raise ValueError("Se requiere OpenFlow13.")

    capacidad = float(config["capacidad_enlace_mbps"])

    if capacidad <= 0:
        raise ValueError("La capacidad debe ser positiva.")

    return config


class TopologiaTesis(Topo):

    def build(self, config):
        capacidad = float(
            config["capacidad_enlace_mbps"]
        )

        # Los switches provienen de la configuracion.
        for sw in config["switches"]:
            self.addSwitch(
                sw,
                protocols=config["protocolo"],
                failMode="secure"
            )

        # Hosts y sus conexiones.
        for host in config["hosts"]:
            self.addHost(
                host["nombre"],
                ip=host["ip"]
            )

            self.addLink(
                host["nombre"],
                host["switch"],
                bw=capacidad
            )

        # Enlaces entre switches.
        for origen, destino in config["enlaces"]:
            self.addLink(
                origen,
                destino,
                bw=capacidad
            )


def iniciar():
    if os.geteuid() != 0:
        raise PermissionError(
            "Mininet debe ejecutarse con sudo."
        )

    config = cargar_configuracion()

    topo = TopologiaTesis(config=config)

    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=False,
        build=False
    )

    # Punto de conexion para OS-Ken.
    # El controlador se implementara en la actividad siguiente.
    net.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6653
    )

    try:
        net.build()
        net.start()

        print("\n" + "=" * 60)
        print("TOPOLOGIA SDN DESPLEGADA")
        print("=" * 60)

        print("Switches:", len(net.switches))
        print("Hosts:", len(net.hosts))
        print(
            "Enlaces entre switches declarados:",
            len(config["enlaces"])
        )

        print(
            "Capacidad configurada:",
            config["capacidad_enlace_mbps"],
            "Mbps"
        )

        print("Protocolo:", config["protocolo"])
        print("Modo de fallo: secure")
        print("=" * 60)

        print(
            "\nEntrando a Mininet CLI para "
            "verificar la red desplegada.\n"
        )

        CLI(net)

    finally:
        net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    iniciar()
