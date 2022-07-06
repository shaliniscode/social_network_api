import email
import re
import os
import time

from flask import Flask, request, render_template, abort, jsonify, g 
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_httpauth import HTTPBasicAuth
import jwt



app = Flask(__name__)

app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

db = SQLAlchemy(app)
auth = HTTPBasicAuth()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(32), index = True)
    password_hash = db.Column(db.String(128))

    def hash_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_auth_token(self, expires_in = 600):
        return jwt.encode(
            {'id': self.id, 'exp': time.time() + expires_in},
            app.config['SECRET_KEY'], algorithm= 'HS256')
        


    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],
             algorithms= ['HS256'])
        except:
            return None
        user = User.query.get(data['id'])
        return user
      
@auth.verify_password
def verify_password(username_or_token, password):
# first trying to autenticate by token
    user = User.verify_auth_token(username_or_token)  
    if not user:
        #try authneticate using username or password
        user = User.query.filter_by(username = username_or_token).first()
        if not user or  not user.verify_password(password):
            return False
    g.user = user
    return True



@app.route('/api/users', methods = ['POST', 'GET'])
def new_user():
    email = None
    if request.method == 'GET':
        pass

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if email is None or password is None:
            abort(400)
    
        if User.query.filter_by(username=email).first() is not None:

            abort(500)
        
        user = User(username=email)
        user.hash_password(password)
        db.session.add(user)
        db.session.commit()

    return render_template('login.html')
   

@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    new_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms= ['HS256'])
    return jsonify({'token': token, 'duration': 600})


@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!'% g.user.username})



#Run server
if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(debug=True)





#username and password combination example to test 
# computer password
# 111 password.