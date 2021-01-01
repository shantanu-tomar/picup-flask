import os, re, boto3

from flask import Flask, request
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from werkzeug.security import generate_password_hash, check_password_hash 
from sqlalchemy.orm import validates
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


app = Flask(__name__)
app.config.from_object(os.environ['FLASK_APP_SETTINGS'])
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ['FLASK_JWT_SECRET_KEY']
app.config['JWT_HEADER_TYPE'] = 'Token'

api = Api(app, prefix="/api")
db = SQLAlchemy(app)
jwt = JWTManager(app)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["5 per minute"],
)

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), index=True, unique=True, nullable=False)
    password = db.Column(db.String())

    def __init__(self, username, password):
        self.username = username
        self.password = generate_password_hash(password)

    @validates('username') 
    def validate_username(self, key, username):
        if not username:
            raise AssertionError('No username provided.')
        
        if User.query.filter(User.username == username).first():
            raise AssertionError('Username is already in use.')
        
        if len(username) < 5 or len(username) > 20:
            raise AssertionError('Username must be between 5 and 20 characters.')
        return username
    
    def __repr__(self):
        return str(self.id)
    
    def serialize(self):
        return {
            'id': self.id, 
            'username': self.username,
        }

    def check_password(self, password):
        return check_password_hash(self.password, password)


class Signup(Resource):
    def post(self):
        username = request.form.get('username')
        password = request.form.get('password')
        
        try:
            user = User(username=username, password=password)
            db.session.add(user)
            db.session.commit()
        except AssertionError as e:
            return {'error': e}, 400

        access_token = create_access_token(identity=str(user.id))

        return {'token': access_token, 'username': user.username}, 201

class LoginApi(Resource):
    def post(self):
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user is None:
            return {'error': 'User with that username does not exist.'}, 400

        authorized = user.check_password(password)
        if not authorized:
            return {'error': 'Email or password invalid'}, 401
      
        access_token = create_access_token(identity=str(user.id))
        return {'token': access_token, 'username': user.username}, 200


class UploadImage(Resource):
    @jwt_required
    def post(self):
        BUCKET_NAME=os.environ['MY_AWS_STORAGE_BUCKET_NAME']
        img = request.files['image']

        if img:
            s3 = boto3.client(
                's3',
                aws_access_key_id=os.environ['MY_AWS_ACCESS_KEY_ID'],
                aws_secret_access_key=os.environ['MY_AWS_SECRET_ACCESS_KEY'],
            )
            filename = secure_filename(img.filename)
            #img.save(filename)
            s3.upload_file(
                Bucket=BUCKET_NAME,
                Filename=filename,
                Key=filename
            )
            url = s3.generate_presigned_url(
                ClientMethod='get_object',
                Params={
                    'Bucket': BUCKET_NAME,
                    'Key': filename
                }
            )

            return {'image': url, 'name': filename}, 201


api.add_resource(Signup, '/signup')
api.add_resource(LoginApi, '/login')
api.add_resource(UploadImage, '/upload')

if __name__ == '__main__':
    app.run()