#from flask import Flask
#from flask_restful import Resource, Api

#app = Flask(__name__)
#api = Api(app)


#class HelloWorld(Resource):
#    def get(self):
#        return {'hello': 'world'}


#api.add_resource(HelloWorld, '/')

#if __name__ == '__main__':
#    app.run(debug=True)
import os

from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config.from_object(os.environ['FLASK_APP_SETTINGS'])
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

from database.models import User

if __name__ == '__main__':
    app.run()