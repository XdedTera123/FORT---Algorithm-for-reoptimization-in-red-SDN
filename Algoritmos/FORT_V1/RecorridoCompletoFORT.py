
#!/usr/bin/env python3
"""Recorrido guiado de FORT V1: Etapa 01 a Etapa 06.

El usuario ejecuta los comandos en la terminal indicada.
El programa muestra instrucciones, evidencia y pausas
para tomar capturas.

No modifica automaticamente las reglas OpenFlow.
"""

import json
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTADOS = ROOT / "resultados/etapa06"

PREFIJOS = {
    "estado": ("fort_capturas_estado", "FORT_Estado_"),
    "decision": ("fort_decisiones", "FORT_Decision_"),
    "plan": ("fort_planes", "FORT_Plan_"),
    "preflight": ("fort_validaciones", "FORT_Preflight_"),
    "ejecucion": ("fort_ejecuciones_reales", "FORT_Resultado_"),
}

# M = Mininet
# C = Controlador OS-Ken
# G = Terminal Ubuntu del guion

PASOS = [
    (1, 1, "Definicion de la topologia SDN", "G", [
        "cd ~/Desktop/Tesis-SDN",
        "python3 -m json.tool config/escenario.json",
        "Verifica 8 switches, 4 hosts y 12 enlaces."
    ], "config"),

    (1, 2, "Despliegue del entorno virtualizado", "M", [
        "EN UNA NUEVA TERMINAL UBUNTU:",
        "cd ~/Desktop/Tesis-SDN",
        "sudo python3 topologia/Topologia.py",
        "CUANDO APAREZCA mininet>:",
        "nodes",
        "net",
        "links",
        "sh ovs-vsctl show"
    ], None),

    (1, 3, "Configuracion de rutas principales", "C y M", [
        "TERMINAL C - Inicia el controlador:",
        "FORT_EJECUTAR=0 OSKEN_HUB_TYPE=eventlet .venv/bin/python controlador/IniciarOSKen.py",
        "Espera que conecten los 8 switches.",
        "TERMINAL M:",
        'sh for s in s1 s2 s3 s4 s5 s6 s7 s8; do printf "$s: "; ovs-vsctl get Controller "$s" is_connected; done',
        "sh python3 herramientas/MostrarRuta.py h1 h2",
        "pingall"
    ], None),

    (1, 4, "Instalacion de Fast Failover", "M", [
        "sh ovs-ofctl -O OpenFlow13 dump-groups s1",
        "sh ovs-ofctl -O OpenFlow13 dump-flows s1",
        "Verifica grupos type=ff, buckets y watch_port.",
        "Revisa la cantidad de grupos en la consola C."
    ], None),

    (1, 5, "Verificacion de recuperacion automatica", "M", [
        "link s1 s2 up",
        "sh python3 herramientas/MostrarRuta.py h1 h2",
        "link s1 s2 down",
        "sh python3 herramientas/MostrarRuta.py h1 h2",
        "pingall",
        "Comprueba ruta H1-S1-S4-S2-H2.",
        "DEJA S1-S2 ABAJO."
    ], None),

    (2, 1, "Fallo controlado y captura con trafico", "C y M", [
        "TERMINAL C: Deten el controlador con Ctrl+C.",
        "Reinicia en modo piloto:",
        "FORT_EJECUTAR=1 FORT_MODO=piloto OSKEN_HUB_TYPE=eventlet .venv/bin/python controlador/IniciarOSKen.py 2>&1 | tee resultados/etapa06/FORT_Consola_Piloto.log",
        "TERMINAL M: S1-S2 debe seguir DOWN.",
        "Ejecuta:",
        'py exec(open("herramientas/ProbarFORTConTrafico.py").read(), {"net":net,"__name__":"__main__"})',
        "Espera la finalizacion del ensayo de 35 segundos.",
        "Espera tambien FORT EJECUTOR: resultado: ...json",
        "NO realices otra prueba mientras capturamos evidencias."
    ], "run"),

    (2, 2, "Registro del forwarding activo FS", "G", [
        "Observa las 12 comunicaciones post-FF.",
        "Identifica las rutas desviadas."
    ], "fs"),

    (2, 3, "Registro de proteccion instalada PS", "G", [
        "Observa los grupos, buckets y respaldos inferidos."
    ], "ps"),

    (2, 4, "Medicion de recursos ocupados y disponibles RS", "G", [
        "Identifica los enlaces con mayor utilizacion.",
        "Recuerda: MLU es el maximo promedio entre enlaces."
    ], "rs"),

    (2, 5, "Construccion del estado FS + PS + RS", "G", [
        "Comprueba que los tres componentes provienen",
        "de una sola captura coordinada."
    ], "integrado"),

    (3, 1, "Actualizacion de la topologia", "G", [
        "Comprueba los enlaces operativos tras S1-S2 DOWN."
    ], "topo"),

    (3, 2, "Calculo de caminos y enlaces criticos", "G", [
        "Observa los caminos candidatos por comunicacion.",
        "Identifica los enlaces mas cargados."
    ], "criticos"),

    (3, 3, "Generacion adaptativa de Targets", "G", [
        "Comprueba Beam Search, presupuesto automatico,",
        "Targets evaluados y tiempo de busqueda."
    ], "busqueda"),

    (3, 4, "Estimacion de carga de cada Target", "G", [
        "Compara la MLU FS modelada con la MLU Target.",
        "No confundas valores modelados con observados."
    ], "estimacion"),

    (3, 5, "Filtrado de Targets mediante Pareto", "G", [
        "Comprueba el frente Pareto y los candidatos.",
        "El algoritmo no certifica el optimo global."
    ], "pareto"),

    (4, 1, "Comparacion Target versus FS", "G", [
        "Observa que comunicaciones cambian de ruta.",
        "Compara los caminos anteriores y propuestos."
    ], "comparar"),

    (4, 2, "Identificacion de operaciones OpenFlow", "G", [
        "Revisa FlowMods, VLAN y grupos FF propuestos."
    ], "operaciones"),

    (4, 3, "Dependencias y orden de actualizacion", "G", [
        "Observa el orden logico de actualizacion.",
        "Esto no certifica consistencia por paquete."
    ], "orden"),

    (4, 4, "Generacion de multiples Transitions", "G", [
        "Observa las alternativas de Transition.",
        "Relaciona las alternativas con el Target."
    ], "transitions"),

    (4, 5, "Reconstruccion de estados intermedios", "G", [
        "Examina la serie modelada de MLU.",
        "Son estados logicos, no mediciones reales."
    ], "intermedios"),

    (5, 1, "Verificacion de factibilidad", "G", [
        "Compara admisibilidad del modelo y preflight.",
        "Revisa las alternativas bloqueadas."
    ], "factibilidad"),

    (5, 2, "Calculo de Final MLU", "G", [
        "Comprueba la MLU final MODELADA."
    ], "final"),

    (5, 3, "Calculo de Peak MLU", "G", [
        "Comprueba la MLU maxima LOGICA de la Transition."
    ], "peak"),

    (5, 4, "Calculo del costo de reconfiguracion", "G", [
        "Compara operaciones estimadas y registradas."
    ], "costo"),

    (5, 5, "Seleccion de Target-Transition", "G", [
        "Observa la pareja preliminar seleccionada.",
        "Comprueba la preferencia tras preflight."
    ], "seleccion"),

    (6, 1, "Integracion y ejecucion piloto de FORT", "C, G y M", [
        "TERMINAL G: consulta el resultado mostrado abajo.",
        "TERMINAL C: revisa los eventos FORT EJECUTOR.",
        "TERMINAL M, con S1-S2 DOWN:",
        "pingall",
        "sh python3 herramientas/MostrarRuta.py h1 h2",
        "sh python3 herramientas/MostrarRuta.py h1 h3",
        "Comprueba conectividad despues del rollback."
    ], "ejecucion"),
]


def cargar(nombre, identificador):
    carpeta, prefijo = PREFIJOS[nombre]

    archivo = (
        RESULTADOS / carpeta /
        (prefijo + identificador + ".json")
    )

    if not archivo.is_file():
        print("PENDIENTE:", archivo)
        return {}

    try:
        return json.loads(
            archivo.read_text(encoding="utf-8")
        )
    except (OSError, ValueError) as error:
        print("ERROR DE LECTURA:", error)
        return {}


def mostrar(valor):
    print(
        json.dumps(
            valor,
            indent=2,
            ensure_ascii=False,
            default=str
        )
    )


def evidencia(tipo, identificador):

    if tipo == "config":
        archivo = ROOT / "config/escenario.json"
        d = json.loads(
            archivo.read_text(encoding="utf-8")
        )

        print("Switches:", len(d["switches"]))
        print("Hosts:", len(d["hosts"]))
        print("Enlaces:", len(d["enlaces"]))
        print(
            "Capacidad:",
            d["capacidad_enlace_mbps"],
            "Mbps"
        )
        return

    if not identificador:
        return

    datos = {
        nombre: cargar(nombre, identificador)
        for nombre in PREFIJOS
    }

    s = datos["estado"]
    d = datos["decision"]
    p = datos["plan"]
    v = datos["preflight"]
    x = datos["ejecucion"]

    par = p.get(
        "pareja_preferida_preliminar"
    ) or {}

    target_id = par.get("target_id")

    target = next(
        (
            t for t in p.get("targets", [])
            if t.get("target_id") == target_id
        ),
        {}
    )

    pareja = next(
        (
            q for q in p.get("parejas", [])
            if q.get("transition_id") ==
            par.get("transition_id")
        ),
        {}
    )

    verific = next(
        (
            q for q in v.get("targets", [])
            if q.get("target_id") == target_id
        ),
        {}
    )

    # ETAPA 02

    if tipo == "fs":
        for c in s.get("fs", {}).get(
            "comunicaciones", []
        ):
            print(
                f'{c["origen"]}->{c["destino"]}:',
                " -> ".join(
                    c["ruta_seleccionada"]
                )
            )

    elif tipo == "ps":
        ps = s.get("ps", {})

        print(
            "Grupos FF:",
            ps.get("cantidad_grupos_ff")
        )

        print(
            "Buckets:",
            ps.get("cantidad_buckets_ff")
        )

        print(
            "Respaldos inferidos:",
            ps.get(
                "grupos_con_respaldo_inferido"
            )
        )

        for c in s.get("fs", {}).get(
            "comunicaciones", []
        ):
            for g in c.get("grupos_ff", []):
                if g.get("modo_inferido") == "RESPALDO":
                    print(
                        f'{c["origen"]}->{c["destino"]}',
                        g
                    )

    elif tipo == "rs":
        rs = s.get("rs", {})

        print(
            "MLU FF observada:",
            rs.get(
                "maxima_utilizacion_observada_pct"
            ),
            "%"
        )

        enlaces = sorted(
            rs.get("direcciones", []),
            key=lambda e: e.get(
                "utilizacion_observada_pct", 0
            ),
            reverse=True
        )

        for e in enlaces[:5]:
            print(
                e.get("origen"),
                "->",
                e.get("destino"),
                e.get(
                    "utilizacion_observada_pct"
                ),
                "%"
            )

    elif tipo == "integrado":
        print("Fallo:", s.get("fallo"))

        print(
            "FS comunicaciones:",
            s.get("fs", {}).get("cantidad")
        )

        print(
            "PS grupos:",
            s.get("ps", {}).get(
                "cantidad_grupos_ff"
            )
        )

        print(
            "RS direcciones operativas:",
            s.get("rs", {}).get(
                "cantidad_direcciones_operativas"
            )
        )

        print(
            "Captura atomica:",
            s.get("captura_atomica")
        )

    # ETAPA 03

    elif tipo == "topo":
        t = d.get(
            "topologia_target_preferido", {}
        )

        print(
            "Enlace fallado:",
            t.get("enlace_fallado")
        )

        print("Enlaces operativos:")
        mostrar(
            t.get("enlaces_operativos", [])
        )

    elif tipo == "criticos":
        print("Caminos candidatos:")

        mostrar(
            d.get(
                "caminos_enumerados_por_comunicacion"
            )
        )

        print("Tres enlaces mas criticos:")

        mostrar(
            d.get(
                "enlaces_priorizados_fs", []
            )[:3]
        )

    elif tipo == "busqueda":
        print("Metodo:", d.get("metodo"))

        print(
            "Targets evaluados:",
            d.get("targets_evaluados")
        )

        print(
            "Tiempo de busqueda:",
            d.get("tiempo_busqueda_s"),
            "s"
        )

        print(
            "Parada:",
            d.get("motivo_parada")
        )

        print("Presupuesto automatico:")
        mostrar(
            d.get("presupuesto_calculado", {})
        )

    elif tipo == "estimacion":
        print(
            "MLU FS modelada:",
            d.get("mlu_fs_modelada_pct"),
            "%"
        )

        print("Target:", target_id)

        print(
            "MLU Target modelada:",
            target.get("final_mlu_pct"),
            "%"
        )

    elif tipo == "pareto":
        print(
            "Targets explorados:",
            d.get("targets_evaluados")
        )

        print("Candidatos Pareto:")

        mostrar(
            d.get("candidatas_pareto", [])
        )

    # ETAPA 04

    elif tipo == "comparar":
        for c in target.get(
            "planes_por_comunicacion", []
        ):
            print(
                f'{c["origen"]}->{c["destino"]}'
            )

            print(
                " FS:",
                " -> ".join(c["ruta_fs"])
            )

            print(
                " TARGET:",
                " -> ".join(c["ruta_target"])
            )

    elif tipo == "operaciones":
        print("Target:", target_id)

        for c in verific.get(
            "comunicaciones", []
        ):
            print(
                c.get("comunicacion"),
                "| Switch:",
                c.get("switch_ingreso"),
                "| VLAN:",
                c.get("vlan_nueva"),
                "| Grupo:",
                c.get("group_id_nuevo"),
                "| FlowMods:",
                len(
                    c.get(
                        "flowmods_preparacion", []
                    )
                )
            )

    elif tipo == "orden":
        print(
            "Transition:",
            pareja.get("transition_id")
        )

        print("Orden de activacion:")

        mostrar(
            pareja.get(
                "orden_activacion_logica", []
            )
        )

    elif tipo == "transitions":
        print(
            "Parejas modeladas:",
            p.get(
                "cantidad_parejas_modeladas"
            )
        )

        print(
            "Transitions del Target:",
            target_id
        )

        mostrar(
            target.get(
                "transitions_preliminares", []
            )
        )

    elif tipo == "intermedios":
        print(
            "Transition:",
            pareja.get("transition_id")
        )

        print(
            "MLU de estados logicos:"
        )

        mostrar(
            pareja.get(
                "serie_estados_logicos_mlu_pct", []
            )
        )

    # ETAPA 05

    elif tipo == "factibilidad":
        print(
            "Parejas modeladas:",
            p.get(
                "cantidad_parejas_modeladas"
            )
        )

        print(
            "Admisibles en modelo:",
            p.get(
                "cantidad_parejas_admisibles_modelo"
            )
        )

        print(
            "Preflight compatibles:",
            v.get(
                "targets_con_preparacion_compatible"
            )
        )

        print(
            "Bloqueados:",
            v.get("targets_bloqueados")
        )

        for t in v.get("targets", []):
            if t.get("bloqueos"):
                print(
                    t.get("target_id"),
                    t["bloqueos"][:2]
                )

    elif tipo == "final":
        print(
            "MLU FS modelada:",
            p.get("mlufs_modelada_pct"),
            "%"
        )

        print(
            "Final MLU modelada:",
            pareja.get("final_mlu_pct"),
            "%"
        )

    elif tipo == "peak":
        print(
            "Peak MLU modelada:",
            pareja.get("peak_mlu_pct"),
            "%"
        )

        print(
            "Estados intermedios:"
        )

        mostrar(
            pareja.get(
                "serie_estados_logicos_mlu_pct", []
            )
        )

    elif tipo == "costo":
        print(
            "Costo estimado del Target:"
        )

        mostrar(
            target.get(
                "operaciones_cambio_estimadas", {}
            )
        )

        print(
            "Operaciones ejecutadas en piloto:"
        )

        mostrar(
            x.get("operaciones", {})
        )

    elif tipo == "seleccion":
        print(
            "Pareja preliminar del modelo:"
        )

        mostrar(
            p.get(
                "pareja_preferida_preliminar"
            )
        )

        print(
            "Preferencia tras preflight:"
        )

        mostrar(
            v.get(
                "pareja_preferida_preflight"
            )
        )

    # ETAPA 06

    elif tipo == "ejecucion":
        print(
            "Estado del piloto:",
            x.get("estado")
        )

        print(
            "Transition:",
            x.get("transition_id")
        )

        print("Fases ejecutadas:")

        mostrar(
            x.get("etapas", [])
        )

        print(
            "Rollback:",
            x.get("rollback_piloto")
        )

        print(
            "MLU FF observada:",
            x.get("mlu_ff_observada_pct"),
            "%"
        )

        print(
            "MLU post-FORT observada:",
            x.get(
                "mlu_post_fort_observada_pct"
            ),
            "%"
        )

        print(
            "Diferencia exploratoria:",
            x.get("mejora_observada_pp"),
            "p.p."
        )

        print(
            "Limitacion:",
            x.get("comparabilidad")
        )


def nuevo_run(inicio):
    carpeta = (
        RESULTADOS /
        "fort_ejecuciones_reales"
    )

    archivos = sorted(
        carpeta.glob(
            "FORT_Resultado_*.json"
        ),
        key=lambda p: p.stat().st_mtime
    )

    archivos = [
        p for p in archivos
        if p.stat().st_mtime >= inicio - 2
    ]

    if not archivos:
        return None

    return archivos[-1].stem.removeprefix(
        "FORT_Resultado_"
    )


def main():

    if not (
        ROOT / "config/escenario.json"
    ).exists():
        raise SystemExit(
            "El archivo debe estar dentro "
            "de Tesis-SDN/herramientas/"
        )

    print(
        "\nRECORRIDO METODOLOGICO FORT V1"
    )

    print(
        "26 actividades documentables"
    )

    print(
        "M = Mininet | C = OS-Ken | "
        "G = Guion Ubuntu"
    )

    print(
        "Ejecuta manualmente los comandos "
        "en la terminal correspondiente."
    )

    inicio = time.time()
    identificador = None

    for etapa, act, titulo, terminal, comandos, tipo in PASOS:

        print(
            "\n" + "=" * 78
        )

        print(
            f"ETAPA {etapa:02d} - "
            f"ACTIVIDAD {act:02d}"
        )

        print(titulo)

        print(
            "TERMINAL:",
            terminal
        )

        print("=" * 78)

        for numero, comando in enumerate(
            comandos, 1
        ):
            print(
                f"{numero}. {comando}"
            )

        input(
            "\nEjecuta los comandos anteriores. "
            "Pulsa ENTER para revisar evidencia..."
        )

        if tipo == "run":
            while True:
                identificador = nuevo_run(
                    inicio
                )

                if identificador:
                    print(
                        "ENSAYO NUEVO SELECCIONADO:",
                        identificador
                    )
                    break

                print(
                    "Todavia no existe un nuevo "
                    "resultado piloto."
                )

                respuesta = input(
                    "ENTER para revisar nuevamente "
                    "o SALIR: "
                )

                if respuesta.strip().upper() == "SALIR":
                    raise SystemExit(
                        "Recorrido detenido."
                    )

        else:
            evidencia(
                tipo,
                identificador
            )

        print(
            "\n" + "#" * 78
        )

        print(
            f"### TOMAR CAPTURA ###"
        )

        print(
            f"ETAPA {etapa:02d} - "
            f"ACTIVIDAD {act:02d}"
        )

        print(
            f"Archivo: "
            f"E{etapa:02d}_A{act:02d}.png"
        )

        print(
            "Captura Mininet, OS-Ken o "
            "el guion segun corresponda."
        )

        print("#" * 78)

        input(
            "Cuando guardes la captura, "
            "pulsa ENTER para continuar..."
        )

    print(
        "\nRECORRIDO FINALIZADO"
    )

    print(
        "Hasta ETAPA 06 - ACTIVIDAD 01."
    )

    print(
        "E06 actividades 02-05 pendientes "
        "de validacion experimental formal."
    )

    print(
        "No presentar mediciones exploratorias "
        "como resultados concluyentes."
    )


if __name__ == "__main__":
    main()
