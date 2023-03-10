import pandas as pd
import json
import sqlite3

def storeFilesInDB(conn):
    # alerts
    alerts = pd.read_csv("../data/alerts.csv")
    alerts.to_sql("alerts", conn, if_exists="replace", index=False)

    # devices
    with open("../data/devices.json", "r") as f:
        devices = json.load(f)

    c = conn.cursor()

    # create tables
    c.execute('''CREATE TABLE IF NOT EXISTS devices (id TEXT, ip TEXT, localizacion TEST, responsable_id TEXT, analisis_id INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS responsable (nombre TEXT PRIMARY KEY, telefono TEXT, rol TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS analisis (id INTEGER PRIMARY_KEY, puertos_abiertos TEXT, no_puertos_abiertos INTEGER, servicios INTEGER, servicios_inseguros INTEGER, vulnerabilidades_detectadas INTEGER)''')

    for d in devices:
        responsable = d['responsable']
        c.execute("INSERT OR IGNORE INTO responsable VALUES (?, ?, ?)", (responsable['nombre'], responsable['telefono'], responsable['rol']))
        analisis = d['analisis']
        if analisis["puertos_abiertos"] == 'None':
            ports = 0
        else:
            ports = len(analisis["puertos_abiertos"])
        c.execute("INSERT INTO analisis (puertos_abiertos, no_puertos_abiertos, servicios, servicios_inseguros, vulnerabilidades_detectadas) VALUES (?, ?, ?, ?, ?)", (json.dumps(analisis['puertos_abiertos']), ports, analisis['servicios'], analisis['servicios_inseguros'], analisis['vulnerabilidades_detectadas']))
        analisis_id = c.lastrowid
        c.execute("INSERT INTO devices (id, ip, localizacion, responsable_id, analisis_id) VALUES (?, ?, ?, ?, ?)", (d['id'], d['ip'], d['localizacion'], responsable['nombre'], analisis_id))

    conn.commit()

def showInfo(conn):
    devices = pd.read_sql_query("SELECT * from devices", conn)
    print("NÚMERO DE DISPOSITIVOS: " + str(len(devices.index)))
    #alerts = pd.read_sql_query("SELECT * from alerts", conn)
    # print("NÚMERO DE ALERTAS: " + str(len(alerts.index)))
    c = conn.cursor()
    no_alerts = c.execute("SELECT count(*) from alerts").fetchone()[0]
    print("NÚMERO DE ALERTAS: " + str(no_alerts))
    analysis = pd.read_sql_query("SELECT * from analisis", conn)
    mean = analysis['no_puertos_abiertos'].mean()
    std = analysis['no_puertos_abiertos'].std()
    print("NÚMERO MEDIO DE PUERTOS ABIERTOS: " + str(mean))
    print("DESVIACIÓN ESTÁNDAR DEL NÚMERO DE PUERTOS ABIERTOS: " + str(std))
    mean = analysis['servicios_inseguros'].mean()
    std = analysis['servicios_inseguros'].std()
    print("NÚMERO MEDIO DE SERVICIOS INSEGUROS DETECTADOS: " + str(mean))
    print("DESVIACIÓN ESTÁNDAR DEL NÚMERO DE SERVICIOS INSEGUROS DETECTADOS: " + str(std))
    mean = analysis['vulnerabilidades_detectadas'].mean()
    std = analysis['vulnerabilidades_detectadas'].std()
    print("NÚMERO MEDIO DE VULNERABILIDADES DETECTADAS : " + str(mean))
    print("DESVIACIÓN ESTÁNDAR DEL NÚMERO DE VULNERABILIDADES DETECTADAS: " + str(std))
    min = analysis["no_puertos_abiertos"].min()
    max = analysis["no_puertos_abiertos"].max()
    print("NÚMERO MÁXIMO DE PUERTOS ABIERTOS EN UN DISPOSITIVO: " + str(max))
    print("NÚMERO MÍNIMO DE PUERTOS ABIERTOS EN UN DISPOSITIVO: " + str(min))
    min = analysis["vulnerabilidades_detectadas"].min()
    max = analysis["vulnerabilidades_detectadas"].max()
    print("NÚMERO MÁXIMO DE VULNERABILIDADES DETECTADAS EN UN DISPOSITIVO: " + str(max))
    print("NÚMERO MÍNIMO DE VULNERABILIDADES DETECTADAS EN UN DISPOSITIVO: " + str(min))



if __name__ == '__main__':
    conn = sqlite3.connect("database.sqlite")
    # storeFilesInDB(conn)
    showInfo(conn)
    conn.close()