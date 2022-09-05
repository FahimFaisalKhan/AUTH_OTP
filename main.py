
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
# from flask_migrate import Migrate
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os
import smtplib
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.orm import relationship
from dotenv import load_dotenv

from email.mime.text import MIMEText
app = Flask(__name__)
load_dotenv()
app.config['SECRET_KEY'] = os.getenv("SECRET")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    "URI").replace("://", "ql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
# migrate = Migrate(app, db)
# CREATE TABLE IN DB

serialzr = URLSafeTimedSerializer(
    os.environ.get("SECRET"))
'''IMPORTANT: INITIALIZING FLASK LOGINMANAGER '''
login_manager = LoginManager()

login_manager.init_app(app)

'''IMPORTANT: LOADING THE USER IN CURRENT SESSION'''

my_mail = os.environ.get("MAIL")
mail_pass = os.getenv("PASS")


def send_mail(reciever_mail, link):

    html = open("templates/email.html", 'r')
    msg = MIMEText(html.read().format(link=link), 'html')
    msg['Subject'] = "Validation"
    msg['From'] = my_mail
    msg['To'] = reciever_mail
    server = smtplib.SMTP(host='smtp.gmail.com', port=587)
    server.starttls()
    server.login(my_mail, mail_pass)
    text = msg.as_string()
    a = server.sendmail(my_mail, reciever_mail, text)
    print(a)
    server.quit()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = 'auth_prac'
    __table_args__ = ({'schema': 'flask_blog'})
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String())
    name = db.Column(db.String(1000))
    child_device = relationship('Devices', back_populates="parent", lazy=True)

    def __init__(self, mail, pas, name):
        self.email = mail
        self.password = pas
        self.name = name

    def __repr__(self):
        return f'this is {self.id} no. object'


class Devices(db.Model):
    __tablename__ = 'devices'
    __table_args__ = ({'schema': 'flask_blog'})
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("flask_blog.auth_prac.id"))
    parent = relationship('User', back_populates='child_device', lazy=True)
    device_ip = db.Column(db.String(250), unique=True, nullable=False)


# Line below only required once, when creating DB.
db.create_all()


@app.route('/')
def home():
    '''IMPORTANT: current_user.is_authenticated RETURNS TRUE IF SESSION USER IS LOGGED IN'''
    print(request.remote_addr)
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':
        email = request.form.get('email')
        if email:
            user_exist = User.query.filter_by(
                email=email).first()

            if not user_exist:
                '''TODO: NOTE: GENERATING HASH AND ADDING SALTS(how many times i wanna hash each hash)'''

                hash_salted_pass = generate_password_hash(
                    password=request.form.get('password'), method="pbkdf2:sha256", salt_length=16)
                # IMPORTANT: USING URLSafeTimedSerializer TO EMBED TOKEN INTO SERIALIZED_URL/serializer LINK THAT THE USER WOULD INSIDE EMAIL
                token = serialzr.dumps(email, salt='confirmation')
                link = url_for('register', name=request.form.get(
                    'name'), token=token,  pas=hash_salted_pass, _external=True)
                send_mail(email, link)
                flash('please verify your email')
                return redirect(url_for('register'))

            else:
                '''NOTE: USING FLASH MESSAGE FOR THIS SOME WORK IS DONE IN CORRESPONDING HTML PAGE IN THIS CASE
                REGISTER.HTML'''
                flash(f'Email already exists ')
                return redirect(url_for('register'))
        else:
            flash("Please fill up the Email field")
    if request.args.get('token'):
        token = request.args.get('token')
        name = request.args.get('name')
        email = request.args.get('email')
        hashed_pas = request.args.get('pas')
        # IMPORTANT: USING URLSafeTimedSerializer TO EXTRACT EMAIL FROM serializer IF THE SERIALIZED_URL WITH THE
        #  SIMILAR TOKEN AND SALT WAS CLICKED IN THE EMAIL
        try:
            email = serialzr.loads(
                token, salt='confirmation', max_age=120)
        except:
            return "<h1> Something Went Wrong!</h1>"
        if email:

            new_user = User(mail=email, name=name, pas=hashed_pas)
            db.session.add(new_user)
            db.session.commit()
            device = Devices(user_id=new_user.id,
                             device_ip=request.remote_addr)
            db.session.add(device)
            db.session.commit()

            flash("Successfully Registered , Now you nan Login !")
            return redirect(url_for('login'))

    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == "POST":

        user = User.query.filter_by(email=request.form.get(
            'email')).first()
        if user:
            '''TODO:NOTE: CHECKING IF THE PASSWORD MATCHES WITH THE HASH SAVED IN DATABASE'''
            correct_pass = check_password_hash(
                pwhash=user.password, password=request.form.get('password'))
            if correct_pass:
                '''IMPORTANT:'''
                user_devices = Devices.query.filter_by(user_id=user.id)
                for device in user_devices:
                    print(device.device_ip, 'This is ip')
                login_user(user)
                return redirect(url_for('secrets', name=user.name, logged_in=True))
            else:
                flash("wrong pasword")
                return redirect(url_for('login'))
        else:
            flash('Incorrect Email')

            return redirect(url_for('login'))

    return render_template("login.html")


'''IMPORTANT: @login_required SO THAT UNAUTHORIZED PEOPLE CAN NOT ACCESS THE PAGE'''


@app.route('/secrets')
@login_required
def secrets():
    name = request.args.get('name')
    logged_in = request.args.get('logged_in')
    return render_template("secrets.html", name=name, logged_in=logged_in)


@app.route('/logout')
@login_required
def logout():
    '''IMPORTANT:'''
    logout_user()

    return redirect(url_for('home'))


@app.route('/download')
def download():
    '''IMPORTANT:TODO:NOTE: LETTING THE USER TO DOWNLOAD STATIC FILES WITH send_from_directory()'''
    return send_from_directory(app.static_folder, 'static', filename='files/cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
