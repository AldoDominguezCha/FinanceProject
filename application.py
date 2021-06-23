import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

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
    """Show portfolio of stocks"""
    user = db.execute('SELECT * FROM users WHERE id=?', session.get('user_id'))
    if len(user) != 1:
        return apology('Fatal error retrieving information related to the user')
    stocks = db.execute('SELECT * FROM stocks WHERE user_id=? AND total_shares > 0', session.get('user_id'))
    holdings_value = 0
    index = 1
    for stock in stocks:
        result = lookup(stock['symbol'])
        if not result:
            return apology('The lookup function failed')
        stock['company'] = result['name']
        stock['price'] = result['price']
        stock['index'] = index
        holdings_value += float(stock['price'])*float(stock['total_shares'])
        index += 1
    return render_template('index.html', user=user[0], stocks=stocks, holdings_value=holdings_value)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get('symbol')
        shares = request.form.get('shares')
        if not symbol:
            return apology("You need to provide a stock symbol")
        if not shares:
            return apology("You need to provide the number of shares")
        if any(c.isalpha() for c in shares):
            return apology('Inavlid value for the number of shares')
        if shares.find('.') != -1:
            return apology("The number of shares must be an integer")
        if int(shares) < 0:
            return apology("The number of shares must be a positive integer")
        stockInfo = lookup(symbol)
        if not stockInfo:
            return apology("No results were found")
        total = float(stockInfo['price'])*int(shares)
        user = db.execute("SELECT * FROM users WHERE id=?", session.get('user_id'))[0]
        if user['cash'] < total:
            return apology('You do not have enough money to complete the operation')
        else:
            remaining = user['cash'] - total
            if remaining < 0:
                return apology('There has been a fatal error in the transaction')
            db.execute('UPDATE users SET cash=? WHERE id=?', remaining, session.get('user_id'))
            db.execute('INSERT INTO buys(user_id, symbol, price, shares) VALUES(?,?,?,?)',
                       session.get('user_id'), symbol, stockInfo['price'], int(shares))
            previous_shares = db.execute('SELECT * FROM stocks WHERE user_id=? AND symbol=?', session.get('user_id'), symbol)
            if len(previous_shares) > 1:
                return apology('Fatal error when consulting previous number of shares')
            elif len(previous_shares) == 0:
                db.execute('INSERT INTO stocks(user_id, symbol, total_shares) VALUES(?,?,?)',
                           session.get('user_id'), symbol, int(shares))
            else:
                new_amount = int(previous_shares[0]['total_shares']) + int(shares)
                db.execute('UPDATE stocks SET total_shares=? WHERE user_id=? AND symbol=?',
                           new_amount, session.get('user_id'), symbol)
            return redirect("/")
    return render_template('buy.html')


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    buys = db.execute('SELECT * FROM buys WHERE user_id=?', session.get('user_id'))
    sells = db.execute('SELECT * FROM sells WHERE user_id=?', session.get('user_id'))
    user = db.execute('SELECT * FROM users WHERE id=?', session.get('user_id'))
    username = user[0]['username']
    indexBuy = 1
    for buy in buys:
        result = lookup(buy['symbol'])
        buy['company'] = result['name']
        buy['index'] = indexBuy
        indexBuy += 1
    indexSell = 1
    for sell in sells:
        result = lookup(buy['symbol'])
        sell['company'] = result['name']
        sell['index'] = indexSell
        indexSell += 1
    return render_template('history.html', buys=buys, sells=sells, username=username)


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
        symbol = request.form.get('symbol')
        if not symbol:
            return apology("You need to provide a stock symbol")
        results = lookup(symbol)
        if not results:
            return apology("No results were found")
        print(results)
        return render_template('quoted.html', results=results)
    return render_template('quote.html')


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username").replace(" ", "")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username or username == "":
            return apology("You need to provide an username")
        taken = db.execute("SELECT * FROM users WHERE username=?", username)
        if len(taken) > 0:
            return apology("The username is already taken")
        if not password or not confirmation:
            return apology("You need to provide a password and confirm it")
        if password != confirmation:
            return apology("The passwords don't match")

        db.execute("INSERT INTO users(username, hash) VALUES(?,?)", username, generate_password_hash(password))

        return redirect("/login")

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get('symbol')
        shares = request.form.get('shares')

        if not symbol:
            return apology('No stock was specified')
        if not shares:
            return apology('You need to provide the number of shares')
        if shares.find('.') != -1:
            return apology('The number of shares must be an integer number')
        if int(shares) <= 0:
            return apology('The number of shares must be a positive integer')
        stocks = db.execute('SELECT * FROM stocks WHERE user_id=?', session.get('user_id'))
        current_shares = 0
        for stock in stocks:
            if symbol == stock['symbol']:
                current_shares = stock['total_shares']
        if current_shares < int(shares):
            return apology('You do not have enough shares from this stock to complete the operation')
        current_shares -= int(shares)
        db.execute('UPDATE stocks SET total_shares=? WHERE user_id=? AND symbol=?', current_shares, session.get('user_id'), symbol)
        stockInfo = lookup(symbol)
        if not stockInfo:
            return apology('There was a fatal error trying to consult the current price')
        current_price = stockInfo['price']
        total_value = float(current_price)*int(shares)
        user = db.execute('SELECT * FROM users WHERE id=?', session.get('user_id'))
        if len(user) != 1:
            return apology('Fatal error trying to retrieve the user')
        current_cash = float(user[0]['cash']) + total_value
        db.execute('UPDATE users SET cash=? WHERE id=?', current_cash, session.get('user_id'))
        db.execute('INSERT INTO sells(user_id, symbol, price, shares) VALUES(?,?,?,?)',
                   session.get('user_id'), symbol, current_price, int(shares))
        return redirect("/")

    stocks = db.execute('SELECT * FROM stocks WHERE user_id=? AND total_shares > 0', session.get('user_id'))
    for stock in stocks:
        result = lookup(stock['symbol'])
        stock['company'] = result['name']
        stock['price'] = result['price']
    return render_template('sell.html', stocks=stocks, length=len(stocks))


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
