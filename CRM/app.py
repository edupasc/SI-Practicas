import os

from flask import *
import sqlite3
import requests
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from forms import *
from werkzeug.urls import url_parse
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config['SECRET_KEY'] = '38463fec0601eac83c5530f838ba8b1a0ccf3d67'
login_manager = LoginManager(app)
login_manager.login_view = "login"
db_dir = "..\\ETL\\database.sqlite"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.abspath(db_dir)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
from models import User




@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)




conn = sqlite3.connect("../ETL/database.sqlite", check_same_thread=False)

@app.route('/')
@login_required
def index():
    return render_template("index.html")

@app.route("/top-ips")
@login_required
def problematic_ips():
    number = request.args.get("number")
    if int(number) <= 0:
        return render_template("error.html", reason="el número de IPs a consultar no puede ser menor que cero.")
    curs = conn.cursor()
    curs.execute("SELECT origen, COUNT(*) as num_alertas FROM alerts WHERE prioridad = 1 GROUP BY origen ORDER BY num_alertas DESC LIMIT ?", (number,))
    resultados = curs.fetchall()
    return render_template('problematic_ips.html', resultados=resultados, number=number)

@app.route("/top-devices")
@login_required
def top_devices():
    number = request.args.get("number")
    if int(number) <= 0:
        return render_template("error.html", reason="el número de dispositivos a consultar no puede ser menor que cero.")
    curs = conn.cursor()
    curs.execute("SELECT ip, SUM(servicios_inseguros + vulnerabilidades_detectadas) as insecurities FROM analisis GROUP BY ip ORDER BY insecurities DESC LIMIT ?", (number,))
    resultados = curs.fetchall()
    return render_template("top_devices.html", resultados=resultados, number=number)

@app.route("/last-vulns")
@login_required
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
    curs=conn.cursor()
    curs.execute("SELECT DISTINCT d.id FROM devices d JOIN analisis a ON d.ip = a.ip WHERE a.servicios_inseguros / a.servicios > 0.33 LIMIT ?",(number,))
    resultados = curs.fetchall()
    cursP = conn.cursor()
    cursP.execute("SELECT DISTINCT d.id, d.ip, d.localizacion, d.responsable_id FROM devices d JOIN analisis a ON d.ip = a.ip WHERE a.servicios_inseguros / a.servicios > 0.33 LIMIT ?",(number,))
    resultadosP = cursP.fetchall()
    cursN = conn.cursor()
    cursN.execute("SELECT DISTINCT d.id, d.ip, d.localizacion, d.responsable_id FROM devices d JOIN analisis a ON d.ip = a.ip WHERE a.servicios_inseguros / a.servicios < 0.33")
    resultadosN = cursN.fetchall()

    return render_template("dangerous_devices.html", number=number, infoPocoVulnerable=infoPocoVulnerable, infoPeligroso=infoPeligroso, resultados=resultados, resultadosP=resultadosP, resultadosN=resultadosN)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect("/")
    form = LoginForm()
    if form.validate_on_submit():
        user = User.get_by_email(form.email.data)
        if user is not None and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            next_page = request.args.get("next")
            if not next_page or url_parse(next_page).netloc != '':
                    next_page = "/"
            return redirect(next_page)
    return render_template("login.html", form=form)

@app.route("/signup", methods=["GET", "POST"])
def signUpForm():
    if current_user.is_authenticated:
        return redirect("/")
    form = SignupForm()
    error = None
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        user = User.get_by_email(email)
        if user is not None:
            error = f'El email {email} ya ha sido utilizado por otro usuario'
        else:
            user = User(name=name, email=email)
            user.set_password(password)
            user.save()
            login_user(user, True)
            next_page = request.args.get("next", None)
            if not next_page or url_parse(next_page).netloc != "":
                next_page = "/"
            return redirect(next_page)
    return render_template("sign_up.html", form=form, error=error)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/")



if __name__ == '__main__':
    app.run(debug=True)
