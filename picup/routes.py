import os, boto3

from flask import request, render_template
from flask_restful import Api, Resource
from flask_jwt_extended import create_access_token, jwt_required
from werkzeug.utils import secure_filename

from .models import User
from . import api, app


class Signup(Resource):
    def post(self):
        body = request.get_json()
        try:
            user = User(**body)
            db.session.add(user)
            db.session.commit()
        except AssertionError as e:
            return {'error': str(e)}, 400

        access_token = create_access_token(identity=str(user.id))

        return {'token': access_token, 'username': user.username}, 201

class LoginApi(Resource):
    def post(self):
        body = request.get_json()
        user = User.query.filter_by(username=body.get('username')).first()
        if user is None:
            return {'error': 'User with that username does not exist.'}, 400

        authorized = user.check_password(body.get('password'))
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
            img.save(filename)
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


api.add_resource(Signup, '/api/signup')
api.add_resource(LoginApi, '/api/login')
api.add_resource(UploadImage, '/api/upload')

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def render_frontend(path):
    return render_template('index.html')
