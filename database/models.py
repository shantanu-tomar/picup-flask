from passlib.hash import sha256_crypt

from app import db


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String())
    password = db.Column(db.String())

    def __init__(self, username, password):
        self.username = name
        self.password = sha256_crypt.encrypt(password)  # sha256_crypt.verify("password", password)

    def __repr__(self):
        return str(self.id)
    
    def serialize(self):
        return {
            'id': self.id, 
            'username': self.username,
        }
