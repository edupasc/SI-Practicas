import pandas as pd
import json
import sqlite3
import matplotlib.pyplot as plt
import calendar

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
    c.execute('''CREATE TABLE IF NOT EXISTS analisis (id INTEGER PRIMARY_KEY, ip TEXT, puertos_abiertos TEXT, no_puertos_abiertos INTEGER, servicios INTEGER, servicios_inseguros INTEGER, vulnerabilidades_detectadas INTEGER)''')


    for d in devices:
        responsable = d['responsable']
        c.execute("INSERT OR IGNORE INTO responsable VALUES (?, ?, ?)", (responsable['nombre'], responsable['telefono'], responsable['rol']))
        analisis = d['analisis']
        if analisis["puertos_abiertos"] == 'None':
            ports = 0
        else:
            ports = len(analisis["puertos_abiertos"])
        c.execute("INSERT INTO analisis (ip, puertos_abiertos, no_puertos_abiertos, servicios, servicios_inseguros, vulnerabilidades_detectadas) VALUES (?, ?, ?, ?, ?, ?)", (d['ip'],json.dumps(analisis['puertos_abiertos']), ports, analisis['servicios'], analisis['servicios_inseguros'], analisis['vulnerabilidades_detectadas']))
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

def infoPriority(conn):
   vulnerabilities = pd.read_sql_query("SELECT DISTINCT a.prioridad, v.vulnerabilidades_detectadas, a.row_num FROM analisis v  JOIN ( SELECT  prioridad, origen, destino, ROW_NUMBER() OVER (ORDER BY prioridad) AS row_num FROM alerts) a  ON v.ip = a.origen OR v.ip = a.destino;", conn)
   alerts = pd.read_sql_query("SELECT * from alerts", conn)
   missingValues = len(alerts.index)
   for j in range(1, 4):
       vulnByPriority = vulnerabilities[(vulnerabilities['prioridad'] == j)]
       missingValues -= len(vulnByPriority.index)
       print("----------------------------------------------------------------------------------------")
       print("Numero de entradas prioridad " + str(j) + ": " + str(len(vulnByPriority.index)))
       print("Media de vulnerabilidades_detectadas con prioridad " + str(j) + ": " + str(vulnByPriority["vulnerabilidades_detectadas"].mean()))
       print("Mediana de vulnerabilidades_detectadas con prioridad " + str(j) + ": " + str(vulnByPriority["vulnerabilidades_detectadas"].median()))
       print("Varianza de vulnerabilidades_detectadas con prioridad " + str(j) + ": " + str(vulnByPriority["vulnerabilidades_detectadas"].var()))
       print("Min de vulnerabilidades_detectadas con prioridad " + str(j) + ": " + str(vulnByPriority["vulnerabilidades_detectadas"].min()))
       print("Máx de vulnerabilidades_detectadas con prioridad " + str(j) + ": " + str(vulnByPriority["vulnerabilidades_detectadas"].max()))

   print("----------------------------------------------------------------------------------------")
   print("Valores ausentes: " + str(missingValues))
def infoDate(conn):
   vulnerabilities = pd.read_sql_query("SELECT DISTINCT a.timestamp, v.vulnerabilidades_detectadas, a.row_num FROM analisis v  JOIN ( SELECT  x.timestamp ,origen, destino, ROW_NUMBER() OVER (ORDER BY prioridad) AS row_num FROM alerts x) a  ON v.ip = a.origen OR v.ip = a.destino;", conn)
   vulnerabilities['timestamp'] = pd.to_datetime(vulnerabilities['timestamp'])
   alerts = pd.read_sql_query("SELECT * from alerts", conn)
   missingValues = len(alerts.index)

   for j in range(7,9):
       vulnByPriority = vulnerabilities[(vulnerabilities['timestamp'].dt.month == j)]
       print("----------------------------------------------------------------------------------------")
       missingValues -= len(vulnByPriority.index)
       print("Numero de entradas del mes " + str(j) + ": " + str(len(vulnByPriority.index)))
       print("Media de vulnerabilidades_detectadas del mes " + str(j) + ": " + str(vulnByPriority["vulnerabilidades_detectadas"].mean()))
       print("Mediana de vulnerabilidades_detectadas del mes " + str(j) + ": " + str(vulnByPriority["vulnerabilidades_detectadas"].median()))
       print("Varianza de vulnerabilidades_detectadas del mes " + str(j)+ ": " + str(vulnByPriority["vulnerabilidades_detectadas"].var()))
       print("Min de vulnerabilidades_detectadas del mes " + str(j)+ ": " + str(vulnByPriority["vulnerabilidades_detectadas"].min()))
       print("Máx de vulnerabilidades_detectadas del mes " + str(j) + ": " + str(vulnByPriority["vulnerabilidades_detectadas"].max()))

def graphs(conn):
    curs=conn.cursor()

    # 10 IPs más problemáticas
    curs.execute("SELECT origen, COUNT(*) as num_alertas FROM alerts WHERE prioridad = 1 GROUP BY origen ORDER BY num_alertas DESC LIMIT 10")
    ip = []
    n= []
    for rows in curs.fetchall():
        ip.append(rows[0])
        n.append(rows[1])
    plt.bar(ip, n, color="gray")
    plt.title('IPs problemáticas')
    plt.xlabel('IP')
    plt.xticks(rotation='vertical')
    plt.ylabel('n alertas')
    plt.subplots_adjust(bottom=0.29)
    plt.show()

    # Numero de alertas por día
    curs.execute("SELECT strftime('%Y-%m-%d',timestamp), COUNT(*) FROM alerts GROUP BY strftime('%Y-%m-%d',timestamp)")
    date = []
    n = []
    for rows in curs.fetchall():
        date.append(rows[0])
        n.append(rows[1])
    plt.plot(date, n, color="gray")
    plt.title('alertas por día')
    plt.xlabel('fecha')
    plt.ylabel('n alertas')
    plt.xticks(rotation=25, ha='right', fontsize=6)
    plt.xticks( range(0, 70, 4))
    plt.subplots_adjust(bottom=0.15)
    plt.show()

    # numero de alertas por categoría
    curs.execute("SELECT clasificacion, COUNT(*) as num_alertas FROM alerts GROUP BY clasificacion")
    category = []
    n = []
    for rows in curs.fetchall():
        category.append(rows[0])
        n.append(rows[1])
    plt.bar(category, n, color="gray")
    plt.title('alertas por categorías')
    plt.xlabel('categoría')
    plt.ylabel('alertas')
    plt.xticks(rotation=25, ha='right', fontsize=6)
    plt.subplots_adjust(bottom=0.29, left=0.2)
    plt.show()

    #la 4 es la traviesa
    """
    # dispositivos más vulnerables
    curs.execute("SELECT id, SUM(servicios_inseguros + vulnerabilidades_detectadas) FROM analisis GROUP BY id")
    device = []
    n = []
    for rows in curs.fetchall():
        device.append(rows[0])
        n.append(rows[1])
    plt.bar(device, ncolor="gray")
    plt.title('dispositivos vulnerables')
    plt.xlabel('dispositivos')
    plt.ylabel('n vulnerabilidades')
    plt.xticks(rotation='vertical')
    plt.show()
    """

    # media de puertos abiertos frente a servicios inseguros
    curs.execute("SELECT servicios_inseguros,AVG(no_puertos_abiertos) FROM analisis GROUP BY servicios_inseguros")
    service = []
    ports = []
    for rows in curs.fetchall():
        service.append(rows[0])
        ports.append(rows[1])
    plt.bar(service, ports, color="gray")
    plt.title('relación puertos abiertos - servicios inseguros')
    plt.xlabel('servicions inseguros')
    plt.ylabel('puertos abiertos')
    plt.show()

    # media de puertos abiertos frente al total de servicios detectados
    curs.execute("SELECT servicios,AVG(no_puertos_abiertos) FROM analisis GROUP BY servicios")
    service = []
    ports = []
    for rows in curs.fetchall():
        service.append(rows[0])
        ports.append(rows[1])
    plt.bar(service, ports, color="gray")
    plt.title('relación puertos abiertos - servicios detectados')
    plt.xlabel('servicios detectados')
    plt.ylabel('puertos abiertos')
    plt.show()

    """
    print("----------------------------------------------------------------------------------------")
    print("Valores ausentes: " + str(missingValues))
    """

if __name__ == '__main__':
    conn = sqlite3.connect("database.sqlite")
    #storeFilesInDB(conn)
    showInfo(conn)
    infoPriority(conn)
    infoDate(conn)
    graphs(conn)
    conn.close()