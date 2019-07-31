import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd
purchase = []
renderinfo = []
# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    id = str(session["user_id"])
    cash = usd(db.execute("SELECT * FROM users WHERE id = :idx;",idx=id)[0]["cash"])
    holdings = []
    for entry in db.execute("SELECT * FROM :idx",idx=id):
        ticker = str(entry["ticker"])
        shares = int(entry["amount"])
        values = lookup(ticker)
        price = round(float(values["price"]),2)
        valued = shares*price
        price = usd(price)
        valued = usd(valued)
        row = [ticker,shares,price,valued]
        holdings.append(row)
    return render_template("index.html",holdings=holdings,cash=cash)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    global purchase
    global renderinfo
    id = str(session["user_id"])
    if request.method == "GET":
        return render_template("buy.html")
    elif request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)
        if not request.form.get("shares"):
            return apology("must provide shares", 400)
        try:
            int(request.form.get("shares"))
        except:
            return apology("invalid input, is not number",400)

        if int(request.form.get("shares")) < 0:
            return apology("invalid input, is less than zero",400)
        values = lookup(request.form.get("symbol"))
        if not values:
            return apology("stock does not exist", 400)
        shares = int(request.form.get("shares"))
        value = float(values["price"])
        values["price"] = usd(float(values["price"]))
        cost = round(value*shares,2)
        symbol = values["symbol"]
        rows = db.execute("SELECT * FROM users WHERE id = :idx",
        idx=id)
        cash= rows[0]["cash"]
        balance = round(cash-cost,2)
        if cash-cost < 0:
            return apology("You don't have enough cash to do that", 400)
        purchase = [balance,symbol,shares,id,cost]

        balance = usd(balance)
        cash = usd(cash)
        cost = usd(cost)
        renderinfo = [values, cost, shares, cash, balance]
        return redirect("/confirmationbuy")

@app.route("/confirmationbuy", methods=["POST","GET"])
@login_required
def confirmationbuy():
    global renderinfo
    if request.method == "GET":
        return render_template("confirmationbuy.html",values=renderinfo[0],cost=renderinfo[1],shares=renderinfo[2],cash=renderinfo[3],balance=renderinfo[4])
    elif request.method == "POST":
        global purchase
        db.execute("UPDATE users SET cash = :balance WHERE id = :id;",balance = purchase[0],id=purchase[3])
        rows = db.execute("SELECT * FROM :id WHERE ticker = :symbol",
        id=purchase[3],symbol=purchase[1])
        id=purchase[3]
        print(purchase[2])
        number = renderinfo[2]
        name = id+"history"
        if len(rows)==1:
            purchase[2] = purchase[2]+int(rows[0]["amount"])
            db.execute("UPDATE :id SET amount = :shares WHERE ticker = :symbol;",id=purchase[3],shares=purchase[2],symbol=purchase[1])
            db.execute("Insert INTO :id(state,ticker,amount,transactionprice,transactiontime) Values(:state,:symbol,:shares,:transactionprice,:transactiontime)",id=name,state="buy",symbol=purchase[1],shares=number,transactionprice=purchase[4],transactiontime= datetime.now())
        else:
            db.execute("Insert INTO :id(ticker,amount,purchasetime) Values(:symbol,:shares,:purchasetime)",id=purchase[3],symbol=purchase[1],shares=purchase[2],purchasetime= datetime.now())
            db.execute("Insert INTO :id(state,ticker,amount,transactionprice,transactiontime) Values(:state,:symbol,:shares,:transactionprice,:transactiontime)",id=name,state="buy",symbol=purchase[1],shares=number,transactionprice=purchase[4],transactiontime= datetime.now())
        return redirect("/")


@app.route("/check", methods=["GET"])
def check():
    USERNAMES = []
    for rows in db.execute("SELECT * FROM users WHERE 1 = 1"):
        i = rows["username"]
        USERNAMES.append(i)
    q = request.args.get("username")
    if len(q) > 0:
        for username in USERNAMES:
            if username == q:
                return jsonify(False)
        return jsonify(True)
    else:
        return jsonify(False)

@app.route("/history")
@login_required
def history():
    id = str(session["user_id"])
    name = id+"history"
    cash = usd(db.execute("SELECT * FROM users WHERE id = :idx;",idx=id)[0]["cash"])
    holdings = []
    states=[]
    for entry in db.execute("SELECT * FROM :idx",idx=name):
        state = str(entry["state"])
        ticker = str(entry["ticker"])
        shares = int(entry["amount"])
        transactionprice = round(float(entry["transactionprice"]),2)
        transactiontime = str(entry["transactiontime"])
        transactionprice = usd(transactionprice)
        row = [state,ticker,str(shares),transactionprice,transactiontime]
        states.append(state)
        holdings.append(row)
    return render_template("history.html",holdings=holdings,cash=cash,states=states,x=0)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "GET":
        return render_template("quote.html")
    elif request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)
        values = lookup(request.form.get("symbol"))
        if not values:
            return apology("stock does not exist", 400)
        values["price"]=usd(values["price"])
        return render_template("quoted.html", values = values)



@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        #Ensure matching passwords
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords must match", 400)

        #Ensure unique username
        rows = db.execute("SELECT * FROM users WHERE username = :username",username=request.form.get("username"))
        if len(rows) == 1:
            return apology("username taken", 400)
        else:
            password = request.form.get("password")
            password = generate_password_hash(password)
            usernamex = request.form.get("username")
            uid = "NULL"
            cashx = "NULL"
            db.execute("INSERT INTO users (username,hash) VALUES (:username,:hash);",
            username=usernamex,
            hash=password)
            rows = db.execute("SELECT * From users WHERE username = :username;",username=usernamex)
            id = str(rows[0]["id"])
            db.execute("CREATE TABLE ?(ticker TEXT PRIMARY KEY,amount INT,purchasetime DATETIME);",id)
            name = id+"history"
            db.execute("CREATE TABLE ?(state TEXT, ticker TEXT,amount INT,transactionprice FLOAT,transactiontime DATETIME);",name)

            return render_template("registered.html")
    else:
        USERNAMES = []
        for rows in db.execute("SELECT * FROM users WHERE 1 = 1"):
            i = rows["username"]
            USERNAMES.append(i)

        q = request.args.get("q")
        for username in USERNAMES:
            if q == username:
                return render_template("register.html", available = False)

        return render_template("register.html", available = True)

sell = []
renderinfosell = []

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    global sell
    global renderinfosell
    id = str(session["user_id"])
    rows = db.execute("SELECT * FROM users WHERE id = :idx",
        idx=id)
    cash= rows[0]["cash"]


    if request.method == "GET":
        tickers = []
        for entry in db.execute("SELECT * FROM :idx",idx=id):
            ticker = str(entry["ticker"])
            tickers.append(ticker)
        return render_template("sell.html",symbols=tickers)




    else:
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)

        if not request.form.get("shares"):
            return apology("must provide shares", 400)

        values = lookup(request.form.get("symbol"))
        if not values:
            return apology("stock does not exist", 400)

        try:
            int(request.form.get("shares"))
        except:
            return apology("invalid input, is not number",400)

        if int(request.form.get("shares")) < 0:
            return apology("invalid input, is less than zero",400)

        sharesreq = int(request.form.get("shares"))
        symbol = request.form.get("symbol")


        for entry in db.execute("SELECT * FROM :idx",idx=id):
            if entry["ticker"]==request.form.get("symbol"):
                ticker = str(entry["ticker"])
                shares = int(entry["amount"])
                values = lookup(ticker)
                name = str(values["name"])
                price = round(float(values["price"]),2)
                valued = sharesreq*price
                newbal = round(cash+valued,2)
                sell = [ticker,shares,price,sharesreq,valued,cash]
                price = usd(price)
                valued = usd(valued)
                cash = usd(cash)
                newbal=usd(newbal)
                renderinfosell = [ticker,shares,price,sharesreq,valued,cash,name,newbal]
                if shares - sharesreq < 0:
                    return apology("you are trying to sell more stock than you have",400)


                newbal = sell[4]+sell[5]
                shares = sell[1]-sell[3]
                db.execute("UPDATE users SET cash = :balance WHERE id = :idx;",balance = newbal,idx=id)
                rows = db.execute("SELECT * FROM :idx WHERE ticker = :symbol",
                idx=id,symbol=sell[0])
                name = id+"history"
                if shares > 0:
                    db.execute("UPDATE :idx SET amount = :share WHERE ticker = :symbol;",idx=id,share=shares,symbol=sell[0])
                    db.execute("Insert INTO :id(state,ticker,amount,transactionprice,transactiontime) Values(:state,:symbol,:shares,:transactionprice,:transactiontime)",id=name,state="sell",symbol=sell[0],shares=sell[3],transactionprice=sell[4],transactiontime= datetime.now())
                elif shares == 0:
                    db.execute("DELETE FROM :idx WHERE ticker = :symbol",idx=id,symbol=sell[0])
                    db.execute("Insert INTO :id(state,ticker,amount,transactionprice,transactiontime) Values(:state,:symbol,:shares,:transactionprice,:transactiontime)",id=name,state="sell",symbol=sell[0],shares=sell[3],transactionprice=sell[4],transactiontime= datetime.now())
                return redirect("/")

                #return redirect("/confirmationsell")


        return apology("You don't own any of that stock",400)



@app.route("/confirmationsell", methods=["POST","GET"])
@login_required
def confirmationsell():
    id = str(session["user_id"])
    global renderinfosell


    if request.method == "GET":
        return render_template("confirmationsell.html",ticker=renderinfosell[0],shares=renderinfosell[1],price=renderinfosell[2],saleshares=renderinfosell[3],cashgained=renderinfosell[4],balance=renderinfosell[5],name=renderinfosell[6],newbal=renderinfosell[7])


    elif request.method == "POST":
        global sell
        newbal = sell[4]+sell[5]
        shares = sell[1]-sell[3]
        db.execute("UPDATE users SET cash = :balance WHERE id = :idx;",balance = newbal,idx=id)
        rows = db.execute("SELECT * FROM :idx WHERE ticker = :symbol",
        idx=id,symbol=sell[0])
        name = id+"history"
        if shares > 0:
            db.execute("UPDATE :idx SET amount = :share WHERE ticker = :symbol;",idx=id,share=shares,symbol=sell[0])
            db.execute("Insert INTO :id(state,ticker,amount,transactionprice,transactiontime) Values(:state,:symbol,:shares,:transactionprice,:transactiontime)",id=name,state="sell",symbol=sell[0],shares=sell[3],transactionprice=sell[4],transactiontime= datetime.now())
        elif shares == 0:
            db.execute("DELETE FROM :idx WHERE ticker = :symbol",idx=id,symbol=sell[0])
            db.execute("Insert INTO :id(state,ticker,amount,transactionprice,transactiontime) Values(:state,:symbol,:shares,:transactionprice,:transactiontime)",id=name,state="sell",symbol=sell[0],shares=sell[3],transactionprice=sell[4],transactiontime= datetime.now())
        return redirect("/")



@app.route("/changepassword", methods=["GET", "POST"])
def changepassword():
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        #Ensure matching passwords
        elif not request.form.get("newpassword"):
            return apology("must provide new password", 403)

        #Ensure unique username
        rows = db.execute("SELECT * FROM users WHERE username = :username",username=request.form.get("username"))
        if len(rows) < 1:
            return apology("account username does not exist",403)

        password = request.form.get("password")
        print(rows[0]["hash"]+"\n"+password)
        if not check_password_hash(rows[0]["hash"], password):
            return apology("Incorrect password", 403)
        elif check_password_hash(rows[0]["hash"], password):
            newpassword = request.form.get("newpassword")
            newpassword = generate_password_hash(newpassword)
            db.execute("UPDATE users SET hash = :hash WHERE username = :username;",hash = newpassword,username=request.form.get("username"))
            return redirect("/")
    else:
        return render_template("changepassword.html")










def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
