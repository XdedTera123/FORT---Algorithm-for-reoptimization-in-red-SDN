### 01. Importaciones ###
from mininet.cli import CLI #Abre consola interactiva
from mininet.link import TCLink #Conf carac de enlaces 
from mininet.log import info, setLogLevel #imprime msg informativos, cant de msj de Mininet
from mininet.net import Mininet #Construte y adnimistra red simulada
from mininet.node import OVSSwitch, RemoteController #Utiliza Open vSwitch como switch SDN, Conecta al controlador OS-Ken
from mininet.topo import Topo #Clase base para definir la topología

### 02. Definicion Topologia ###
class TopologiaSDN(Topo):

    def build(self):
        ### Recursos ###
        switches = {}

        hosts = (
            ("h1", "10.0.0.1/24", 1),
            ("h2", "10.0.0.2/24", 2),
            ("h3", "10.0.0.3/24", 5),
            ("h4", "10.0.0.4/24", 7)
        )

        enlaces_switches = (
            (1, 2),(1, 3),(1, 4),
            (2, 4),(2, 5),(3, 4),
            (3, 6),(4, 5),(4, 7),
            (5, 8),(6, 7),(7, 8)
        )
        ### Creacion de switches ###
        for numero in range(1,9):
            switches[numero] = self.addSwitch(
                f"s{numero}",
                dpid=f"{numero:016x}",
                protocols="OpenFlow13",
                failMode="secure"
            )
        ### Creacion y conexion de host ###
        for nombre, ip, switch in hosts:
            host = self.addHost(
                nombre,
                ip=ip
            )
            self.addLink(
                host,
                switches[switch]
            )
        ### Definicicion de capcidad para enlace (100Mbps) ###
        for origen, destino in enlaces_switches:
            self.addLink(
                switches[origen],
                switches[destino],
                bw=100
            )

### 03. Despliegue de la red Mininet ###
def main():
    ### Creacion Red-Mininet ###
    red = Mininet(
        topo=TopologiaSDN(),
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )
    ### Configuracion controlador remoto ###
    red.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6653
    )
    ### Inicializacion de la red ###
    try:
        red.start()
        info(
            "\n========================================\n"
            "FORT - TOPOLOGIA SDN INICIADA\n"
            "========================================\n"
        )
        info(
            "Switches: 8\n"
            "Hosts: 4\n"
            "Enlaces entre switches: 12\n"
            "Capacidad nominal: 100 Mbps\n"
            "Protocolo: OpenFlow 1.3\n"
            "Puerto del controlador: 6653\n"
        )
        info(
            "\nComandos de verificacion:\n"
            "nodes\n"
            "net\n"
            "links\n"
            "dump\n"
        )

        ### Abrir consola interactiva de Mininet ###
        CLI(red)
    ### Detener los componentes al salir ###
    finally:
        red.stop()

#### 04. Punto de entrada ###
if __name__ == "__main__":
    setLogLevel("info")
    main()