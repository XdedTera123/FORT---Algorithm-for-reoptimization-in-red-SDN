
#!/usr/bin/env python3
"""Etapa 02 - Actividad 05: integracion y validacion FS + PS + RS."""

import json
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
DIR = BASE / "resultados" / "etapa02"
SALIDA = DIR / "EstadoPostFallo.json"


def leer(ruta):
    return json.loads(ruta.read_text(encoding="utf-8"))


def exigir(condicion, mensaje):
    if not condicion:
        raise RuntimeError(mensaje)


def identificar_fallo(registro):
    fallos = registro["enlaces_fallados_observados"]

    exigir(
        len(fallos) == 1,
        "Se requiere exactamente un enlace fallado"
    )

    enlace = fallos[0]
    return frozenset((
        enlace["extremo_a"],
        enlace["extremo_b"]
    ))


def validar_fs(fs, escenario, fallo):
    hosts = {
        h["nombre"]: h["switch"]
        for h in escenario["hosts"]
    }

    switches = set(escenario["switches"])

    enlaces = {
        frozenset(e)
        for e in escenario["enlaces"]
    }

    adyacencias = enlaces | {
        frozenset((host, sw))
        for host, sw in hosts.items()
    }

    esperados = {
        (a, b)
        for a in hosts
        for b in hosts
        if a != b
    }

    observados = set()

    for flujo in fs["comunicaciones"]:
        par = (flujo["origen"], flujo["destino"])

        exigir(
            par in esperados and par not in observados,
            f"Comunicacion invalida o duplicada: {par}"
        )

        observados.add(par)
        ruta = flujo["ruta_seleccionada"]
        pasos = flujo["pasos_openflow"]

        exigir(
            len(ruta) >= 3
            and ruta[0] == par[0]
            and ruta[-1] == par[1]
            and ruta[1] == hosts[par[0]]
            and ruta[-2] == hosts[par[1]],
            f"Extremos incorrectos: {par}"
        )

        exigir(
            len(pasos) == len(ruta) - 2,
            f"Cantidad de pasos incorrecta: {par}"
        )

        for a, b in zip(ruta, ruta[1:]):
            exigir(
                frozenset((a, b)) in adyacencias,
                f"Salto inexistente: {a}->{b}"
            )

            exigir(
                frozenset((a, b)) != fallo,
                f"Ruta utiliza el enlace fallado: {par}"
            )

        for indice, paso in enumerate(pasos):
            exigir(
                paso["switch"] == ruta[indice + 1]
                and paso["siguiente_nodo"] == ruta[indice + 2]
                and paso["switch"] in switches,
                f"Paso OpenFlow inconsistente: {par}"
            )

    exigir(
        observados == esperados,
        "Faltan comunicaciones en FS"
    )

    exigir(
        fs["cantidad_comunicaciones"] == len(observados),
        "Conteo FS inconsistente"
    )

    return len(observados)


def validar_ps(ps, escenario):
    switches = set(escenario["switches"])

    exigir(
        set(ps["switches"]) == switches,
        "Switches incompletos en PS"
    )

    total_grupos = 0
    total_buckets = 0
    total_reglas = 0

    for sw, datos in ps["switches"].items():
        puertos = {}

        for puerto in datos["puertos"]:
            puertos[str(puerto["numero"])] = puerto
            puertos[puerto["nombre"]] = puerto

        grupos = datos["grupos_fast_failover"]
        ids = set()

        for grupo in grupos:
            gid = grupo["group_id"]

            exigir(
                gid not in ids and grupo["tipo"] == "ff",
                f"Grupo FF duplicado o invalido: {sw}:{gid}"
            )

            ids.add(gid)
            buckets = grupo["buckets"]

            for indice, bucket in enumerate(buckets):
                vigilado = puertos.get(bucket["watch_port"])

                exigir(
                    vigilado is not None,
                    f"Puerto vigilado desconocido: {sw}:{gid}"
                )

                exigir(
                    bucket["indice"] == indice
                    and bucket["puerto_activo"] == vigilado["activo"],
                    f"Estado de bucket inconsistente: {sw}:{gid}"
                )

            elegido = next(
                (
                    b["indice"]
                    for b in buckets
                    if b["puerto_activo"]
                ),
                None
            )

            exigir(
                grupo["bucket_seleccionado_inferido"] == elegido,
                f"Seleccion FF inconsistente: {sw}:{gid}"
            )

            total_buckets += len(buckets)

        for regla in datos["reglas_openflow_proteccion"]:
            exigir(
                all(
                    gid in ids
                    for gid in regla["grupos_referenciados"]
                ),
                f"Regla referencia grupo inexistente: {sw}"
            )

        total_grupos += len(grupos)
        total_reglas += len(
            datos["reglas_openflow_proteccion"]
        )

    exigir(
        total_grupos == ps["cantidad_grupos_ff"]
        and total_buckets == ps["cantidad_buckets_ff"]
        and total_reglas == ps["cantidad_reglas_proteccion"],
        "Totales PS inconsistentes"
    )

    return total_grupos, total_buckets, total_reglas


def validar_rs(rs, escenario, fallo):
    enlaces = {
        frozenset(e)
        for e in escenario["enlaces"]
    }

    esperados = {
        (a, b)
        for enlace in escenario["enlaces"]
        for a, b in (tuple(enlace), tuple(reversed(enlace)))
    }

    observados = set()
    porcentajes = []

    for d in rs["direcciones"]:
        par = (d["origen"], d["destino"])

        exigir(
            par in esperados and par not in observados,
            f"Direccion RS invalida o duplicada: {par}"
        )

        observados.add(par)

        capacidad = d["capacidad_configurada_bps"]
        tasa = d["tasa_tx_bps"]

        exigir(
            capacidad > 0 and tasa >= 0,
            f"Capacidad o tasa invalida: {par}"
        )

        if frozenset(par) == fallo:
            exigir(
                not d["activo"]
                and d["capacidad_operativa_bps"] == 0,
                f"Enlace fallado aparece operativo: {par}"
            )
        else:
            exigir(
                d["activo"]
                and d["capacidad_operativa_bps"] == capacidad,
                f"Estado operativo incorrecto: {par}"
            )

            porcentaje = 100 * tasa / capacidad

            exigir(
                abs(porcentaje - d["utilizacion_pct"]) < 0.01,
                f"Utilizacion inconsistente: {par}"
            )

            porcentajes.append(d["utilizacion_pct"])

    exigir(
        observados == esperados,
        "Direcciones incompletas en RS"
    )

    exigir(
        rs["cantidad_enlaces"] == len(enlaces)
        and rs["cantidad_direcciones"] == len(observados),
        "Totales RS inconsistentes"
    )

    maxima = max(porcentajes) if porcentajes else None

    exigir(
        maxima == rs["maxima_utilizacion_observada_pct"],
        "Maxima utilizacion inconsistente"
    )

    return len(enlaces), len(observados), maxima


def main():
    escenario = leer(BASE / "config" / "escenario.json")

    fs = leer(DIR / "FS_postfallo.json")
    ps = leer(DIR / "PS_postfallo.json")
    rs = leer(DIR / "RS_postfallo.json")

    fallo_fs = identificar_fallo(fs)
    fallo_ps = identificar_fallo(ps)
    fallo_rs = identificar_fallo(rs)

    exigir(
        fallo_fs == fallo_ps == fallo_rs,
        "FS, PS y RS no corresponden al mismo fallo"
    )

    rutas = validar_fs(fs, escenario, fallo_fs)
    grupos, buckets, reglas = validar_ps(ps, escenario)
    enlaces, direcciones, maxima = validar_rs(
        rs, escenario, fallo_fs
    )

    fechas = {}

    for nombre, registro in (
        ("FS", fs),
        ("PS", ps),
        ("RS", rs)
    ):
        fecha = datetime.fromisoformat(
            registro["fecha_utc"]
        )

        exigir(
            fecha.tzinfo is not None,
            f"Fecha sin zona horaria: {nombre}"
        )

        fechas[nombre] = fecha

    inicio = min(fechas.values())
    fin = max(fechas.values())
    separacion = (fin - inicio).total_seconds()

    resultado = {
        "tipo": "Estado_Post_Fast_Failover",
        "generado_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "enlace_fallado": sorted(fallo_fs),
        "validacion": {
            "coincidencia_fallo": True,
            "consistencia_topologica": True,
            "consistencia_interna_fs_ps_rs": True,
            "captura_simultanea": False,
            "separacion_capturas_segundos": separacion,
            "observacion": (
                "Estado compuesto de capturas tomadas "
                "en distintos momentos. Para decisiones "
                "experimentales se requiere una captura "
                "coordinada bajo carga controlada."
            ),
        },
        "fechas_captura_utc": {
            nombre: fecha.isoformat()
            for nombre, fecha in fechas.items()
        },
        "resumen": {
            "rutas_fs": rutas,
            "grupos_ff_ps": grupos,
            "buckets_ff_ps": buckets,
            "reglas_proteccion_ps": reglas,
            "enlaces_rs": enlaces,
            "direcciones_rs": direcciones,
            "maxima_utilizacion_rs_pct": maxima,
        },
        "estado": {
            "FS": fs,
            "PS": ps,
            "RS": rs,
        },
    }

    temporal = SALIDA.with_suffix(".json.tmp")
    temporal.write_text(
        json.dumps(
            resultado,
            indent=2,
            ensure_ascii=False
        ) + "\n",
        encoding="utf-8"
    )
    temporal.replace(SALIDA)

    print("\n=== ESTADO POST-FAST-FAILOVER ===")
    print("Enlace fallado:", " - ".join(
        nodo.upper() for nodo in sorted(fallo_fs)
    ))
    print("FS: ", rutas, "rutas")
    print(
        "PS: ", grupos, "grupos FF,",
        buckets, "buckets,",
        reglas, "reglas"
    )
    print(
        "RS: ", enlaces, "enlaces,",
        direcciones, "direcciones"
    )
    print("Maxima utilizacion:", maxima, "%")
    print("CONSISTENCIA FS + PS + RS: CORRECTA")
    print(
        "Separacion entre capturas:",
        round(separacion / 60, 2), "minutos"
    )
    print("Tipo de registro: COMPUESTO, NO SIMULTANEO")
    print("Archivo generado:", SALIDA)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, KeyError) as error:
        raise SystemExit(f"ERROR: {error}")
