from flask import Flask, render_template, redirect, url_for, request, flash, session, make_response, jsonify
import json
import re
import os.path

# Use bcrypt for password handling
import bcrypt



PASSWORDFILE = 'passwords'
PASSWORDFILEDELIMITER = ":"



app = Flask(__name__)
# The secret key here is required to maintain sessions in flask
app.secret_key = b'8852475abf1dcc3c2769f54d0ad64a8b7d9c3a8aa8f35ac4eb7454473a5e454c'

# Initialize Database file if not exists.
if not os.path.exists(PASSWORDFILE):
    open(PASSWORDFILE, 'w').close()


@app.route('/')
def home():
    if session.get("username"):
        return render_template("loggedin.html", username=session.get("username"))

    return render_template('home.html')


# Display register form
@app.route('/register', methods=['GET'])
def register_get():
    return render_template('register.html')

# Handle registration data
@app.route('/register', methods=['POST'])
def register_post():
    username = request.form['username']
    password = request.form['password']
    password2 = request.form['matchpassword']
    status = checkpass(password, password2)
    if(status != 1):
        return render_template("register.html", error = "password " + status)
    status = checkname(username)
    if(status != 1):
        return render_template("register.html", error = "username " + status)
    if status == 1:
        register_user(username,password)
        return redirect(url_for("login_get"))
    else:

        return render_template("register.html")
    
# Display login form
@app.route('/login', methods=['GET'])
def login_get():
    return render_template('login.html')


# Handle login credentials
@app.route('/login', methods=['POST'])
def login_post():
    usrname = request.form['username']
    password = request.form['password']
    status = login(usrname,password)
    if status == 1:
        session["username"] = usrname
        return redirect("/")
    else:
        return render_template('login.html')



def register_user(name, password):
    password = password.encode('utf-8')
    hashedPassword = bcrypt.hashpw(password, bcrypt.gensalt())
    user = {"name":name,"password":hashedPassword.decode('ascii')}
    with open("passwords.json", "w") as fp:
        list.append(user)
        json.dump(list,fp) 
    
def login(name,password):
    with open("passwords.json", "r") as fp:
        list = json.load(fp)
        for el in list:
            if el["name"] == name:
                password = password.encode("utf-8")
                pass2 = el["password"].encode('ascii')
                if bcrypt.checkpw(password, pass2):
                    return 1
                else:
                    return 0
        return 0
def checkpass(password,pass2):
    if (password != pass2):
        return "not matching"
    if (len(password)<8):
        return "too short"
    elif not re.search("[a-z]", password):
        return "needs lowercase"
    elif not re.search("[A-Z]", password):
        return "needs uppercase"
    elif not re.search("[0-9]", password):
        return "needs number"
    elif re.search("\s", password):
        return "cannot have space"
    else:
        return 1
def checkname(name):
    for el in list:
            if el["name"] == name:
                return "name exists"
    if (len(name)<6):
        return "too short"
    elif re.search("\s", name):
        return "cannot use space"
    else:
        return 1
if __name__ == '__main__':

    # TODO: Add TSL
    with open("passwords.json", "r") as fp:
        list = json.load(fp)
    app.run(debug=True)

