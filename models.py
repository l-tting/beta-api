from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:6979@localhost/vuedb'
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer,nullable= False,primary_key=True)
    username = db.Column(db.String(200),nullable= False)
    email = db.Column(db.String(200),nullable=False,unique=True)
    password = db.Column(db.String(100),nullable=False)


class Product(db.Model):
    __tablename__= 'products'
    id = db.Column(db.Integer,nullable=False,primary_key=True)
    name = db.Column(db.String(200),nullable=False)
    buying_price = db.Column(db.Integer,nullable=False)
    selling_price = db.Column(db.Integer,nullable=False)
    stock_quantity=db.Column(db.Integer,nullable=False)
    product =db.relationship('Sale',backref='saleproduct')

class Sale(db.Model):
    __tablename__ = 'sales'
    id = db.Column(db.Integer,nullable=False,primary_key=True)
    pid = db.Column(db.Integer,db.ForeignKey('products.id'),nullable=False)
    quantity = db.Column(db.Integer,nullable=False)
    created_at =db.Column(db.DateTime,server_default=func.now())

with app.app_context():
    db.create_all()

    
