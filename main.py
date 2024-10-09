from flask import request,jsonify,session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded
from models import app,db,User,Product,Sale,func
from werkzeug.security import generate_password_hash,check_password_hash
from datetime import datetime, timedelta
from flask_cors import CORS
from functools import wraps
from models import User,Product,Sale
import jwt
import secrets


app.secret_key = secrets.token_bytes(16)


#uses get remote address to identify clients by IP address,,automatically uses request.remote_addr to identify client IP
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=['200 per day']
)


#allow all origins
CORS(app, resources={r"/*": {"origins": "*"}})

#fallback error handler for rate limiting
@app.errorhandler(429)
def rate_limit(e):
    return jsonify({
        "error":"Rate limit exceeded",
        "message":"You have exceeded your request limit, try again later"
    }),429


@app.post('/register')
def register_user():
    data = request.json
    email = data['email']
    username = data['username']
    password = data['password']

    existing_user = db.session.query(User).filter(User.email==email).first()
    if existing_user:
        return jsonify({"Message":"User exists please login"})
    try:
        hashed_password =generate_password_hash(password)
        new_user = User(email=email,username=username,password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"Message":"Registration successful"}),201
    except Exception as e:
        return jsonify({"Error registering user":e})



@app.post('/login')
@limiter.limit("5 per minute")
def login_user():
    try:
        data = request.json
        userdata = data['user']
        password = data['password']
        existing_user = db.session.query(User).filter(User.username==userdata or User.email==userdata).first()
        if not existing_user:
            return jsonify({"Login failed":"Confirm login credentials"}), 401
        try:
            if check_password_hash(existing_user.password, password):
                access_token = jwt.encode({"sub": existing_user.username, "exp": datetime.utcnow()+timedelta(minutes=30)}, app.secret_key, algorithm='HS256')
                return jsonify({"message":"Login Successful","access_token":access_token}), 201
            else:
                return jsonify({"Login failed":"Incorrect password"}), 401
        except Exception as e:
            return jsonify({"Error creating access token": str(e)}), 500
    except RateLimitExceeded:
        return jsonify({
            "Error":"Rate limit exceeded",
            "Message":"Too many login attempts,please try again later"
        })
        
    
def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token = request.headers.get("Authorization")
        if token is None:
            return jsonify({"Message":"Token is missing"})
        try:
            data = jwt.decode(token,app.secret_key,algorithms=['HS256'])
            current_user = data['sub']
            return f(current_user,*args,**kwargs)
        except:
            return jsonify({"Error":"Error decoding token,confirm your secret key"})
    return decorated
    

@app.route('/products',methods=['GET','POST'])
# @token_required
def products():
    if request.method == 'POST':
        try:
            data = request.json
            name = data['name']
            buying_price = data['buying_price']
            selling_price = data['selling_price']
            stock_quantity = data['stock_quantity']
            new_product = Product(name=name,buying_price=buying_price,selling_price=selling_price,stock_quantity=stock_quantity)
            db.session.add(new_product)
            db.session.commit()
            return jsonify({"Message":"Product added successfully"}),201
        except Exception as e:
            return jsonify({"Error adding products":e}),500
    elif request.method == 'GET':
        # user = db.session.query(User).filter(current_user==User.username).first()
        # if not user:
        #     return jsonify({"Message":"User not found"}),404

        products = db.session.execute(db.select(Product).order_by(Product.name)).scalars()
        product_data = []
        for product in products:
            product_data.append({
                "id":product.id,
                "name":product.name,
                "buying_price":product.buying_price,
                "selling_price":product.selling_price,
                "stock_quantity":product.stock_quantity
            })
        return jsonify({"products":product_data}),200
    

@app.route('/sales',methods=['GET','POST'])
# @token_required
def sales():
    if request.method == "POST":
        try:
            data = request.json
            pid = data['pid']
            quantity = data['quantity']
            make_sale = Sale(pid =pid,quantity=quantity)
            db.session.add(make_sale)
            db.session.commit()
            return jsonify({"Message":"Sale made successfully"})
        except Exception as e:
            return jsonify({"Error making sale":e})
    elif request.method  == "GET":
        sales = db.session.execute(db.select(Sale).order_by(Sale.id)).scalars()
        sales_data = []
        for sale in sales:
            sales_data.append({
                "id":sale.id,
                "pid":sale.pid,
                "quantity":sale.quantity,
                "created_at":sale.created_at

            })
        return jsonify({"sales":sales_data})

@app.get("/dashboard")
def dashboard():
    sales_per_day = db.session.query(
        func.date(Sale.created_at).label('date'),
        func.sum(Sale.quantity * Product.selling_price).label('total_sales')
    ).join(Product).group_by(func.date(Sale.created_at)).all()

    profit_per_day = db.session.query(
        func.date(Sale.created_at).label('date'),
        func.sum((Sale.quantity * Product.selling_price)-
                (Sale.quantity * Product.buying_price)).label("profit")
    ).join(Product).group_by(func.date(Sale.created_at)).all()

    profit_per_product = db.session.query((Product.name).label('product_name'),
            func.sum((Sale.quantity * Product.selling_price)-(Sale.quantity*Product.buying_price)).label("profit")             
            ).join(Product).group_by('product_name').all()
    
    sales_per_product = db.session.query(
        (Product.name).label("product_name"),
        func.sum(Sale.quantity * Product.selling_price).label("day_sales")
    ).join(Product).group_by('product_name').all()

    sales_data = [{'date':str(day),'total_sales':sales} for day,sales in sales_per_day]
    profit_data =[{'date':str(day),'profit':profit} for day,profit in profit_per_day]
    product_profit = [{"product_name":product,"profit":profit} for product,profit in profit_per_product]
    day_sales = [{"product_name":product,"day_sales":sale} for product,sale in sales_per_product]

    return jsonify({"sales_per_day":sales_data,"profit_per_day":profit_data,"profit_per_product":product_profit,"sales_per_product":day_sales}),200



if __name__ == '__main__':
    app.run(debug=True)