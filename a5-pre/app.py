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
    if status == True:
        return render_template("loggedin.html", username=log_name)

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
    if status == 1:
        register_user(username,password)
        return render_template("login.html")
    else:

        return render_template("register.html")
    
# Display login form
@app.route('/login', methods=['GET'])
def login_get():
    return render_template('login.html')


# Handle login credentials
@app.route('/login', methods=['POST'])
def login_post():
    username = request.form['username']
    password = request.form['password']
    status = login(username,password)
    if status == 1:
        status = True
        log_name = username
        return render_template("loggedin.html", username=log_name)
    else:
        return render_template('login.html')



def register_user(name, password):
    if name in list.keys():
        return render_template("register.html")
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
                    print("xd")
                    return 1
                else:
                    return 0
        return 0
def checkpass(password,pass2):
    if (password != pass2):
        return 0
    if (len(password)<8):
        return 0
    elif not re.search("[a-z]", password):
        return 0
    elif not re.search("[A-Z]", password):
        return 0
    elif not re.search("[0-9]", password):
        return 0
    elif re.search("\s", password):
        return 0
    else:
        return 1
def checkname(name):
    if re.search("\s", name):
        return 0
    else:
        return 1
if __name__ == '__main__':

    # TODO: Add TSL
    status = False
    log_name = None
    with open("passwords.json", "r") as fp:
        list = json.load(fp)
    app.run(debug=True)

