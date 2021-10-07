from sqlite3 import IntegrityError
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


#Line below only required once, when creating DB.
# db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods = ["GET", "POST"])
def register():
    if request.method == "POST":
        if User.query.filter_by(email=request.form.get('email')).first():
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        new_user = User(
            name = request.form.get("name"),
            email = request.form.get("email"),
            password = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)

        return render_template("secrets.html", name=new_user.name)

    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        # Find user by email entered.
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
            # Check stored password hash against entered password hashed.
        elif not check_password_hash(user.password, password):
            flash('Please check your password')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('secrets'))

    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets')
def secrets():
    return render_template("secrets.html", name = current_user.name, logged_in=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

filename = "cheat_sheet.pdf"
@app.route('/download/cheat_sheet', methods = ["GET", "POST"])
def download():
    filename = "cheat_sheet.pdf"
    if current_user.is_authenticated:
        return send_from_directory('./static/files', filename, as_attachment=False)


if __name__ == "__main__":
    app.run(debug=True)
