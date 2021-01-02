from . import db

from werkzeug.security import generate_password_hash, check_password_hash 
from sqlalchemy.orm import validates


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), index=True, unique=True, nullable=False)
    password = db.Column(db.String())

    def __init__(self, username, password, password2):
        self.username = username
        self.password = generate_password_hash(password)

    @validates('username') 
    def validate_username(self, key, username):
        print(username)
        if User.query.filter(User.username == username).first():
            raise AssertionError('Username is already in use.')
        
        if len(username) < 5 or len(username) > 20:
            raise AssertionError('Username must be between 5 and 20 characters.')
        return username
    
    def check_password(self, password):
        return check_password_hash(self.password, password)
