# from flask
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
# third party packages
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

# native packages
from datetime import timedelta, datetime
from functools import wraps
import dotenv



# create the app
app = Flask(__name__)
# create the extension
# configure the SQLite database, relative to the app instance folder

# for sqlite database
# app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"

# for mysql database
app.config["SQLALCHEMY_DATABASE_URI"] = f"mysql+pymysql://{dotenv.get_key('.env', 'MYSQL_USERNAME')}:{dotenv.get_key('.env', 'MYSQL_PASSWORD')}@{dotenv.get_key('.env', 'MYSQL_HOST')}/{dotenv.get_key('.env', 'MYSQL_DATABASE')}"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = dotenv.get_key('.env', 'SECRET_KEY')

# initialize the app with the extension
db = SQLAlchemy(app)


## models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128),  nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'


class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=False, nullable=True)
    license_key = db.Column(db.String(128), unique=True, nullable=False)
    expire_date = db.Column(db.DateTime, nullable=False)
    expired = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<Username {self.username}> <License {self.license_key}>'


## decorators
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except Exception as e:
            return jsonify({'message': 'Token is invalid'}), 403
        return f(*args, **kwargs)
    return decorated


## routes
@app.route('/')
def index():
    return '500 Internal Server Error'


@app.route('/api/create-user', methods=['GET', 'POST'])
@token_required
def create_user():
    if request.method == 'POST':
        data = request.get_json()
        username = data['username']
        password = data['password']
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User created'})
    

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    user = User.query.filter_by(username=username).first()
    if user:
        if check_password_hash(user.password, password):
            token = jwt.encode({'user': username, 'exp': datetime.utcnow() + timedelta(hours=7)}, app.config['SECRET_KEY'])
            return jsonify({'message': 'Logged in', 'token': token})
        else:
            return jsonify({'message': 'Wrong password'})
    else:
        return jsonify({'message': 'Wrong username or password'})
    

@app.route('/api/change-password', methods=['POST'])
@token_required
def change_password():
    data = request.get_json()
    username = data['username']
    password = data['password']
    new_password = data['new_password']
    user = User.query.filter_by(username=username).first()
    if user:
        if check_password_hash(user.password, password):
            hashed_password = generate_password_hash(new_password)
            user.password = hashed_password
            db.session.commit()
            return jsonify({'message': 'Password changed'})
        else:
            return jsonify({'message': 'Wrong password'})
    else:
        return jsonify({'message': 'Wrong username or password'})
    

@app.route('/api/create-license', methods=['POST'])
@token_required
def create_license():
    data = request.get_json()
    username = data['username']
    license_key = data['license_key']
    days = data['days']
    expire_date = datetime.today() + timedelta(days=days)
    new_license = License(username=username, license_key=license_key, expire_date=expire_date)
    db.session.add(new_license)
    db.session.commit()
    return jsonify({'message': 'License created'})


@app.route('/api/delete-license', methods=['POST'])
@token_required
def delete_license():
    data = request.get_json()
    license_key = data['license_key']
    license = License.query.filter_by(license_key=license_key).first()
    if license:
        db.session.delete(license)
        db.session.commit()
        return jsonify({'message': 'License deleted'})
    else:
        return jsonify({'message': 'License not found'})
    

@app.route('/api/update-license', methods=['PUT'])
@token_required
def update_license():
    data = request.get_json()
    license_key = data['license_key']
    days = data['days']
    license = License.query.filter_by(license_key=license_key).first()
    if license:
        license.expire_date = datetime.today() + timedelta(days=days)
        db.session.commit()
        return jsonify({'message': 'License updated'})
    else:
        return jsonify({'message': 'License not found'})


@app.route('/api/list-licenses', methods=['GET'])
@token_required
def licenses():
    licenses = License.query.all()
    licenses_list = []
    for license in licenses:
        license_dict = {
            'id': license.id,
            'username': license.username,
            'license_key': license.license_key,
            'expire_date': license.expire_date,
            'expired': license.expired
        }
        licenses_list.append(license_dict)
    return jsonify(licenses_list)


@app.route('/api/check-license', methods=['POST'])
def check_license():
    data = request.get_json()
    license_key = data['license_key']
    license = License.query.filter_by(license_key=license_key).first()
    if request.headers.get('User-Agent') != 'Code Mail Lite/(v1.0)':
        return jsonify({'message': 'Access denied', 'authenticated': False})
    if license:
        if license.expired or license.expire_date < datetime.today():
            return jsonify({'message': 'License expired', 'authenticated': False})
        else:
            return jsonify({'message': 'License valid', 'expire_date': license.expire_date, 'authenticated': True})
    else:
        return jsonify({'message': 'License not found', 'authenticated': False})



if __name__ == '__main__':
    if dotenv.get_key('.env', 'FLASK_DEBUG') == 'True':
        app.run(debug=True)
    else:
        app.run()