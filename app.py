import os

from datetime import datetime
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)


# Custom filter
app.jinja_env.filters["usd"] = usd


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    total = 0
    id = session["user_id"]
    transactions = db.execute(
        "SELECT username,name,symbol,SUM(CASE WHEN type = 'Buy' THEN shares WHEN type = 'Sell' THEN -shares ELSE 0 END) AS total_shares FROM transactions where username =? GROUP BY symbol having total_shares>=1 ", id)
    remaining = round(db.execute("SELECT cash FROM users where id =?", id)[0]["cash"], 2)
    prices = []
    for transaction in transactions:
        price = lookup(transaction["symbol"])
        value = price["price"] * transaction["total_shares"]
        prices.append({"name": transaction["name"], "price": price["price"], "shares": transaction["total_shares"], "value": value})
        total += value
    total = total + remaining
    return render_template("portfolio.html", transactions=transactions, prices=prices, remaining=remaining, total=round(total, 2))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        user_id = session["user_id"]
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("PROVIDE A SYMBOL")
        shares = request.form.get("shares")
        if not shares:
            return apology("how many do u want to buy?")

        if not shares.isdigit():
            return apology("provide valid shares", 400)

        try:
            info = lookup(symbol)
            cost = round(info["price"], 2)
            total = cost * float(shares)
        except TypeError:
            return apology("INVALID SYMBOL")

        user_cash = db.execute("SELECT * FROM users where id =?", user_id)[0]["cash"]
        cash = user_cash - total
        if cash < 0:
            return apology("NOT ENOUGH CASH")

        db.execute("UPDATE users set cash = ? where id = ?", cash, user_id)
        transaction_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        db.execute("INSERT INTO transactions (username,amount,symbol,type,shares,name,total,time) values(?,?,?,'Buy',?,?,?,?)",
                   user_id, cost, info["symbol"], shares, info["name"], total, transaction_time)
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("select * from transactions where username = ? order by time desc", session["user_id"])
    for transaction in transactions:
        transaction["total"] = round(transaction["total"], 2)
    return render_template("history.html", transactions=transactions)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get(("symbol"))
        if not symbol:
            return apology("PROVIDE A SYMBOL")
        info = lookup(symbol)
        try:
            symbol = info["symbol"]
        except TypeError:
            return apology("Invalid symbol", 400)

        return render_template("quoted.html", symbol=symbol, value=usd(info["price"]))
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        Username = request.form.get("username")
        password = request.form.get("password")
        password_d = request.form.get("confirmation")

        if password != password_d:
            return apology("must provide same password", 400)
        elif not password:
            return apology("must provide password", 400)
        elif not password_d:
            return apology("must provide password", 400)
        elif not Username:
            return apology("must provide username", 400)

        else:
            hash = generate_password_hash(password)
            try:
                db.execute("INSERT INTO users (username, hash ) VALUES (?,?)", Username, hash)
            except ValueError:
                return apology("username already exists", 400)

        rows = db.execute("SELECT * FROM users WHERE username = ?", Username)
        session["user_id"] = rows[0]["id"]
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("PROVIDE SYMBOL")

        shares = request.form.get("shares")
        if not shares:
            return apology("how many do u want to sell?")

        present_shares = db.execute(
            "select SUM(CASE WHEN type = 'Buy' THEN shares WHEN type = 'Sell' THEN -shares ELSE 0 END) AS total_shares from transactions where symbol =? and username=? ", symbol, user_id)
        if int(shares) > present_shares[0]["total_shares"]:
            return apology("NOT ENOGH SHARES")

        info = lookup(symbol)
        cost = round(info["price"], 2)
        total = cost * float(shares)
        user_cash = db.execute("SELECT * FROM users where id =?", user_id)[0]["cash"]
        cash = user_cash + total
        db.execute("UPDATE users set cash = ? where id = ?", cash, user_id)
        transaction_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        db.execute("INSERT INTO transactions (username,amount,symbol,type,shares,name,total,time) values(?,?,?,'Sell',?,?,?,?)",
                   user_id, cost, symbol, shares, info["name"], total, transaction_time)
        return redirect("/")
    else:
        symbols = db.execute("select symbol from transactions where username=? group by symbol ", user_id)
        return render_template("sell.html", symbols=symbols)


@app.route("/reset", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        id = session["user_id"]
        current_password = request.form.get("current_password")
        password = request.form.get("new_password")
        password_d = request.form.get("new_confirmation")

        rows = db.execute("SELECT * FROM users WHERE  id = ?", id)
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], current_password):
            return apology("invalid original password", 403)

        if not password:
            return apology("must provide password", 400)
        elif not password_d:
            return apology("must provide password", 400)
        elif password != password_d:
            return apology("must provide same password", 400)

        hash = generate_password_hash(password)
        db.execute("update users set hash = ? where id = ?", hash, id)

        return render_template("login.html")
    else:
        return render_template("reset.html")
