from flask import *
import sqlite3
import requests
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from models import User
from forms import *
from werkzeug.urls import url_parse
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config['SECRET_KEY'] = '38463fec0601eac83c5530f838ba8b1a0ccf3d67'
login_manager = LoginManager(app)
login_manager.login_view = "login"
db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../ETL/database.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False



@login_manager.user_loader
def load_user(user_id):
    return User.get_user(int(user_id))




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

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect("/")
    form = LoginForm()
    if form.validate_on_submit():
        user = User.get_user(form.email.data)
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
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        user = User(len(User.users)+1, name, email, password)
        conn.cursor().execute("INSERT INTO users VALUES (?, ?, ?, ?, ?)", (user.id, user.name, user.email, user.password, user.is_admin))
        conn.commit()
        login_user(user, True)
        next_page = request.args.get("next", None)
        if not next_page or url_parse(next_page).netloc != "":
            next_page = "/"
        return redirect(next_page)
    return render_template("sign_up.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/")



if __name__ == '__main__':
    app.run(debug=True)
