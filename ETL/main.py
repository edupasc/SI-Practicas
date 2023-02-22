# This is a sample Python script.

# Press Mayús+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

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
    c.execute('''CREATE TABLE IF NOT EXISTS analisis (id INTEGER PRIMARY_KEY, puertos_abiertos TEXT, servicios INTEGER, servicios_inseguros INTEGER, vulnerabilidades_detectadas INTEGER)''')

    for d in devices:
        responsable = d['responsable']
        c.execute("INSERT OR IGNORE INTO responsable VALUES (?, ?, ?)", (responsable['nombre'], responsable['telefono'], responsable['rol']))
        analisis = d['analisis']
        c.execute("INSERT INTO analisis (puertos_abiertos, servicios, servicios_inseguros, vulnerabilidades_detectadas) VALUES (?, ?, ?, ?)", (json.dumps(analisis['puertos_abiertos']), analisis['servicios'], analisis['servicios_inseguros'], analisis['vulnerabilidades_detectadas']))
        analisis_id = c.lastrowid
        c.execute("INSERT INTO devices (id, ip, localizacion, responsable_id, analisis_id) VALUES (?, ?, ?, ?, ?)", (d['id'], d['ip'], d['localizacion'], responsable['nombre'], analisis_id))

    conn.commit()

def showInfo(conn):
    devices = pd.read_sql_query("SELECT * from devices", conn)
    print("NÚMERO DE DISPOSITIVOS: " + str(len(devices.index)))
    # alerts = pd.read_sql_query("SELECT * from alerts", conn)
    # print("NÚMERO DE ALERTAS: " + str(len(alerts.index)))
    c = conn.cursor()
    no_alerts = c.execute("SELECT count(*) from alerts").fetchone()[0]
    print("NÚMERO DE ALERTAS: " + str(no_alerts))





# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    conn = sqlite3.connect("database.sqlite")
    # storeFilesInDB(conn)
    showInfo(conn)
    conn.close()
# See PyCharm help at https://www.jetbrains.com/help/pycharm/
