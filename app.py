import functools

from flask import Flask
import passlib.hash
import pyproj
import geojson
from flask import Flask, request, jsonify, make_response   
from flask_sqlalchemy import SQLAlchemy

from werkzeug.security import generate_password_hash, check_password_hash
import uuid 
import jwt
import datetime
from functools import wraps
import json


app = Flask(__name__)

app.config['SECRET_KEY']='Th1s1ss3cr3t'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///../db.sqlite' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True 

db = SQLAlchemy(app)   


class Users(db.Model):  
   __tablename__ = 'user'
   user_id = db.Column(db.String(50), primary_key=True)
   username = db.Column(db.VARCHAR(50))
   encrypted_password = db.Column(db.VARCHAR(150))
   
class Crs(db.Model):  
   __tablename__ = 'crs'
   crs_id = db.Column(db.Integer(), primary_key=True)
   epsg_code = db.Column(db.VARCHAR(50))
       
   
class User_Crs(db.Model):  
   __tablename__ = 'user_crs'
   user_id = db.Column(db.Integer(), primary_key=True)
   crs_id = db.Column(db.Integer())
    



def token_required(f):  
    @wraps(f)  
    def decorator(*args, **kwargs):

       token = None 

       if 'x-access-tokens' in request.headers:  
          token = request.headers['x-access-tokens'] 
          print(token)
          data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS512', 'HS256']) 
         #  print(data)

       if not token:  
          return jsonify({'message': 'a valid token is missing'})   

       try:  
          data = jwt.decode(token, app.config['SECRET_KEY']) 
          print("datat",data['user_id'])
          current_user = Users.query.filter_by(user_id="1").first() 
         #  return f(current_user, *args, **kwargs) 
         #  print("curr",current_user)
         
       except:
         return jsonify({'message': 'token is invalid'})

       return f(current_user, *args, **kwargs)

                
    return decorator 


# There's username and passwords already in db.sqlite:
#   user1 / password1
#   user2 / password2

def encrypt_password(password: str) -> str:
  return passlib.hash.pbkdf2_sha256.hash(password)


def verify_password(password: str, encypted_password: str) -> str:
  return passlib.hash.pbkdf2_sha256.verify(password, encypted_password)

@app.route('/', methods=[ 'GET'])
def Test():
      return "alive"


@app.route('/login', methods=[ 'POST'])
def login():
        auth =  json.loads(request.data)
    
        # auth = request.authorization   
        # print(auth,auth['username'])
        try:
              if not auth or not auth['username'] or not auth['password']:  
                return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})  
        except:
                return jsonify({'message': 'invalid message'}),401          

        user = Users.query.filter_by(username=auth['username']).first() 
        
        if verify_password(auth['password'],user.encrypted_password):          
          token = jwt.encode({'user_id': user.user_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'],algorithm='HS512').decode('UTF-8')   
          return {'jwt_token':token}   
        return jsonify({'message': 'login required'}),401             

        # return make_response('could not verify',  401, {'WWW.Authentication': 'Basic realm: "login required"'})


@app.route('/projections', methods=[ 'GET'])
@token_required
def projections(current_user):
    n = db.session.query(Crs.epsg_code).\
        join(Users, Users.user_id == Crs.crs_id).\
        join(User_Crs,Users.user_id == User_Crs.user_id).\
        filter(Users.user_id == current_user.user_id).all()
    print(n, jsonify(n))
    print(current_user.user_id)
    return  jsonify(n)


@app.route('/vector/reproject')
def vector_reproject():

    raise NotImplementedError('Implement Me!')

    ## Some sample code to reproject a geojson

    # Target CRS to be read from HTTP request
    target_crs = 'epsg:3857'

    # GeoJSON to be read from HTTP request
    with open('example_vector.geojson') as geojson_file:
      geometry = geojson.load(geojson_file)

    source_crs = geometry['crs']['properties']['name']

    transformer = pyproj.Transformer.from_crs(
      source_crs,
      target_crs,
      always_xy=True,
    )

    reprojected = {
      **geojson.utils.map_tuples(
        lambda c: transformer.transform(c[0], c[1]),
        geometry,
      ),
      **{
        "crs": {
          "type": "name",
          "properties": {
            "name": target_crs
          }
        }
      }
    }


if __name__ == '__main__':
    # Bind on all interfaces so that we can easily
    # map ports when running in a docker container
    app.run(host= '0.0.0.0')
