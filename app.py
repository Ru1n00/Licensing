# from flask
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
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
if dotenv.get_key('.env', 'FLASK_DEBUG') == 'True':
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"
else: 
    # for mysql database
    app.config["SQLALCHEMY_DATABASE_URI"] = f"mysql+pymysql://{dotenv.get_key('.env', 'MYSQL_USERNAME')}:{dotenv.get_key('.env', 'MYSQL_PASSWORD')}@{dotenv.get_key('.env', 'MYSQL_HOST')}/{dotenv.get_key('.env', 'MYSQL_DATABASE')}"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = dotenv.get_key('.env', 'SECRET_KEY')

# initialize the app with the extension
db = SQLAlchemy(app)
migrate = Migrate(app, db)


## models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128),  nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.username}>'


class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=False, nullable=True)
    license_key = db.Column(db.String(128), unique=True, nullable=False)
    expire_date = db.Column(db.DateTime, nullable=False)
    expired = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

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



## utilities
def validate_password(password):
    if len(password) < 8:
        return False
    else:
        return True


## routes
@app.route('/')
def index():
    return '500 Internal Server Error'


## user routes
@app.route('/api/create-user', methods=['GET', 'POST'])
@token_required
def create_user():
    if request.method == 'POST':
        data = request.get_json()
        # get username and password from the request
        username = data.get('username')
        password = data.get('password')

        # check if username and password are not empty
        if username and password:
            # check if username already exists
            user = User.query.filter_by(username=username).first()
            if user:
                return jsonify({'message': 'Username already exists'})
            # check if password is valid
            if validate_password(password):
                hashed_password = generate_password_hash(password)
                new_user = User(username=username, password=hashed_password)
                db.session.add(new_user)
                db.session.commit()
                return jsonify({'message': 'User created'})
            else:
                return jsonify({'message': 'Password is too short'})
        else:
            return jsonify({'message': 'Username or password is missing'})
    

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    # get username and password from the request
    username = data.get('username')
    password = data.get('password')

    # check if username and password are not empty
    if not username or not password:
        return jsonify({'message': 'Username or password is missing'})
    
    # check if username and password are correct
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
    # get username and password from the request
    username = data.get('username')
    password = data.get('password')
    new_password = data.get('new_password')

    # check if username and password are not empty
    if not username or not password or not new_password:
        return jsonify({'message': 'Username, password or new_password is missing'})
    
    # check if username and password are correct
    user = User.query.filter_by(username=username).first()
    if user:
        if check_password_hash(user.password, password):
            if not validate_password(new_password):
                return jsonify({'message': 'Password is too short'})
            hashed_password = generate_password_hash(new_password)
            user.password = hashed_password
            user.updated_at = datetime.utcnow()
            db.session.commit()
            return jsonify({'message': 'Password changed'})
        else:
            return jsonify({'message': 'Wrong usernamer or password'})
    else:
        return jsonify({'message': 'Wrong username or password'})
    

## license routes -- lite
@app.route('/api/create-license', methods=['POST'])
@token_required
def create_license():
    data = request.get_json()
    # get username, license key and days from the request
    username = data.get('username')
    license_key = data.get('license_key')
    days = data.get('days')

    # check if username, license key and days are not empty
    if not username or not license_key or not days:
        return jsonify({'message': 'Username, license key or days are missing'})
    
    try:
        days = int(days)
    except:
        return jsonify({'message': 'Days must be an integer'})
    
    expire_date = datetime.today() + timedelta(days=days)

    # check if license key already exists
    check_license = License.query.filter_by(license_key=license_key).first()
    if check_license:
        return jsonify({'message': 'License already exists'})
    
    # create new license
    new_license = License(username=username, license_key=license_key, expire_date=expire_date)
    db.session.add(new_license)
    db.session.commit()
    return jsonify({'message': 'License created'})


@app.route('/api/delete-license', methods=['POST'])
@token_required
def delete_license():
    data = request.get_json()
    license_key = data.get('license_key')

    # check if username, license key and days are not empty
    if not license_key:
        return jsonify({'message': 'license_key is missing'})
    
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
    license_key = data.get('license_key')
    days = data.get('days')

    # check if license key and days are not empty
    if not license_key or not days:
        return jsonify({'message': 'License key or days are missing'})
    
    # check if days is an integer
    try:
        days = int(days)
    except:
        return jsonify({'message': 'Days must be an integer'})
    
    # check if license key exists
    license = License.query.filter_by(license_key=license_key).first()
    if license:
        license.expire_date = datetime.today() + timedelta(days=days)
        license.updated_at = datetime.utcnow()
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
    license_key = data.get('license_key')

    # check if license key is not empty
    if not license_key:
        return jsonify({'message': 'License key is missing', 'authenticated': False})
    
    
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