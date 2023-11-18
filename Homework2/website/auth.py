from flask import Blueprint, render_template, request, flash, redirect, url_for, json, jsonify, make_response
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db   ##means from __init__.py import db
from flask_login import login_user, login_required, logout_user, current_user
import uuid
from flask_jwt_extended import create_access_token, jwt_required
import datetime
from functools import wraps
from . import app
import jwt, os


app.config['SECRET_KEY'] = 'SecretToken'
auth = Blueprint('auth', __name__)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            print(token)
            return jsonify({'message' : 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
             print(token)
             return jsonify({'message' : 'Token is invalid'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user:
            if check_password_hash(user.password, password):
                token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return jsonify({'token' : token})
                #return render_template("login.html", user=current_user)
                
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')  
            token1 = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")
            return jsonify({{'token' : token1}})  
    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        hashed_password = generate_password_hash(password1, method='sha256')

        if user:
            flash('Email already exists', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
           flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user=User(public_id=str(uuid.uuid4()), email=email, first_name=first_name, password=hashed_password, admin=False)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created!', category='success')
            print(user.public_id)
            return redirect(url_for("views.home"))


    return render_template("sign_up.html", user=current_user)


@auth.route('/users', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    users = User.query.all()
    
    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['email'] = user.email
        user_data['fisrt_name'] = user.first_name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users': output})


@auth.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})
    else:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['email'] = user.email
        user_data['fisrt_name'] = user.first_name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        return jsonify({'user' : user_data})


@auth.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})
    else:
        user.admin = True
        db.session.commit()
        return jsonify({'message': 'User was promoted to admin!'})



@auth.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})
    else:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User was deleted!'})



