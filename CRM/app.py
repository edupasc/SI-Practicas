from flask import *
import sqlite3
import requests


app = Flask(__name__)


def get_cursor():
    conn = sqlite3.connect("ETL/database.sqlite")
    return conn.cursor()

@app.route('/')
def hello_world():
    return render_template("index.html")

@app.route("/top-ips")
def problematic_ips():
    number = request.args.get("number")
    if int(number) <= 0:
        return render_template("error.html", reason="el número de IPs a consultar no puede ser menor que cero.")
    curs = get_cursor()
    curs.execute("SELECT origen, COUNT(*) as num_alertas FROM alerts WHERE prioridad = 1 GROUP BY origen ORDER BY num_alertas DESC LIMIT ?", (number,))
    resultados = curs.fetchall()
    return render_template('problematic_ips.html', resultados=resultados, number=number)

@app.route("/top-devices")
def top_devices():
    number = request.args.get("number")
    if int(number) <= 0:
        return render_template("error.html", reason="el número de dispositivos a consultar no puede ser menor que cero.")
    curs = get_cursor()
    curs.execute("SELECT ip, SUM(servicios_inseguros + vulnerabilidades_detectadas) as insecurities FROM analisis GROUP BY ip ORDER BY insecurities DESC LIMIT ?", (number,))
    resultados = curs.fetchall()
    return render_template("top_devices.html", resultados=resultados, number=number)

@app.route("/last-vulns")
def last_vulns():
    response = requests.get('https://cve.circl.lu/api/last')
    data = response.json()
    vulns = data[:10]
    return render_template('last_vulns.html', vulns=vulns)

@app.route("/dangerous-devices")
def dangerous_devices():
    number = request.args.get("number")
    if int(number) <= 0:
        return render_template("error.html", reason="como no pongas una entrada válida me voy a convertir en la peor de tus pesadillas <3")
    Peligroso = request.args.get("infoPeligroso")
    PocoVulnerable = request.args.get("infoPocoVulnerable")
    if Peligroso:
        infoPeligroso="True"
    else:
        infoPeligroso="False"
    if PocoVulnerable:
        infoPocoVulnerable="True"
    else:
        infoPocoVulnerable="False"
    curs=get_cursor()
    curs.execute("SELECT DISTINCT d.id FROM devices d JOIN analisis a ON d.ip = a.ip WHERE a.servicios_inseguros / a.servicios > 0.33 LIMIT ?",(number,))
    resultados = curs.fetchall()
    cursP = get_cursor()
    cursP.execute("SELECT DISTINCT d.id, d.ip, d.localizacion, d.responsable_id FROM devices d JOIN analisis a ON d.ip = a.ip WHERE a.servicios_inseguros / a.servicios > 0.33 LIMIT ?",(number,))
    resultadosP = cursP.fetchall()
    cursN = get_cursor()
    cursN.execute("SELECT DISTINCT d.id, d.ip, d.localizacion, d.responsable_id FROM devices d JOIN analisis a ON d.ip = a.ip WHERE a.servicios_inseguros / a.servicios < 0.33")
    resultadosN = cursN.fetchall()

    return render_template("dangerous_devices.html", number=number, infoPocoVulnerable=infoPocoVulnerable, infoPeligroso=infoPeligroso, resultados=resultados, resultadosP=resultadosP, resultadosN=resultadosN)


if __name__ == '__main__':
    app.run(debug=True)
