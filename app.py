import binascii
import hashlib
import os
import random
import string
from datetime import date

from flask import Flask, flash, g, redirect, render_template, request, session, url_for

# ---- old version
# import sqlite3
from flask_sqlalchemy import SQLAlchemy

# ---- old version
# def current_directory_databese(): # function in order to know where the Databese is located

#     data = 'data'
#     cantorDatebase = 'cantor.db'
#     sql_DB_Directory = os.path.join(os.getcwd(),data, cantorDatebase)
#     sql_DB_Directory = sql_DB_Directory.replace('\\','/')
#     # print('sql_DB_Directory',sql_DB_Directory)
#     return sql_DB_Directory


# ---- old version
# app_info = {
#     'db_file' : current_directory_databese()
# }

app =Flask(__name__)
# app.config['SECRET_KEY'] = '!'
app.config.from_pyfile('config.cfg')
db = SQLAlchemy(app)


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    currency = db.Column(db.String(5))
    amount = db.Column(db.Integer)
    user = db.Column(db.String(50))
    trans_date = db.Column(db.Date)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    password = db.Column(db.Text)
    is_active = db.Column(db.Boolean)
    is_admin = db.Column(db.Boolean)
# def get_db():
#     if not hasattr(g,'sqlite_db'):
#         conn = sqlite3.connect(app_info['db_file'])
#         conn.row_factory = sqlite3.Row
#         g.sqlite_db = conn
#     return g.sqlite_db


# @app.teardown_appcontext
# def close_db(error):
#         if  hasattr(g,'sqlite_db'):
#             g.sqlite_db .close()





class Currency:
    def __init__(self, code, name, flag):
        self.code = code
        self.name = name
        self.flag = flag

    def __repr__(self):
        return '<Currency {}>'.format(self.code)
    
class CantorOffer:

    def __init__(self) :
        self.currencies = []
        self.denied_codes = []

    def load_offer(self):
        self.currencies.append(Currency('USD', 'Dollar', 'flag_usa.png'))
        self.currencies.append(Currency('EUR', 'Euro', 'flag_europe.png'))
        self.currencies.append(Currency('JPY', 'Yen', 'flag_japan.png'))
        self.currencies.append(Currency('GPB', 'Pound', 'flag_england.png'))
        self.denied_codes.append('USD')

    def get_by_code(self, code):
        for currency in self.currencies:
            if currency.code ==code:
                return currency
        return Currency('unknow','unknow' , 'flag_pirat.png')


class UserPass:

    def __init__(self, user='', passsword=''):
        self.user = user
        self.password = passsword
        self.email = ''
        self.is_valid = False
        self.is_admin = False

    def hash_password(self):
        """Hash a password for storing."""
        # the value generated using os.urandom(60)
        os_urandom_static = b"ID_\x12p:\x8d\xe7&\xcb\xf0=H1\xc1\x16\xac\xe5BX\xd7\xd6j\xe3i\x11\xbe\xaa\x05\xccc\xc2\xe8K\xcf\xf1\xac\x9bFy(\xfbn.`\xe9\xcd\xdd'\xdf`~vm\xae\xf2\x93WD\x04"
        salt = hashlib.sha256(os_urandom_static).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac('sha512', self.password.encode('utf-8'), salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash).decode('ascii')
    
    def verify_password(self, stored_password, provided_password):
        """Verify a stored password against one provided by user"""
        salt = stored_password[:64]
        stored_password = stored_password[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha512', provided_password.encode('utf-8'), salt.encode('ascii'),  100000)
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')
        return pwdhash == stored_password

    def get_random_user_pasword(self):
        random_user = ''.join(random.choice(string.ascii_lowercase)for i in range(3))
        self.user = random_user

        password_characters = string.ascii_letters #+ string.digits + string.punctuation
        random_password = ''.join(random.choice(password_characters)for i in range(3))
        self.password = random_password

    
    def login_user(self):

        user_record = User.query.filter(User.name == self.user).first()
        # db = get_db()
        # sql_statement = 'SELECT id, name, email, password, is_active, is_admin from users where name=?;'
        # cur = db.execute(sql_statement,[self.user])
        # user_record = cur.fetchone()

        if user_record != None and self.verify_password(user_record.password, self.password):
            return user_record
        else:
            self.user = None
            self.password = None
            return None
        
    def get_user_info(self):
        db_user = User.query.filter(User.name == self.user).first()
        # db = get_db()
        # sql_statement = 'SELECT id, name, email, password, is_active, is_admin from users where name=?;'
        # cur = db.execute(sql_statement,[self.user])
        # db_user = cur.fetchone()

        if db_user  == None:
            self.is_valid = False
            self.is_admin = False
            self.email = ''
        elif db_user.is_active !=1:
            self.is_valid = False
            self.is_admin = False
            self.email = db_user.email
        else:
            self.is_valid = True
            self.is_admin = db_user.is_admin
            self.email = db_user.email




            




@app.route('/init_app')
def init_app():
    db.create_all()
    # check if there are users defined (at least one active admin required)
    # db=get_db()
    # sql_statement= 'select count(*) as cnt from users where is_active and is_admin;'
    # cur = db.execute(sql_statement)
    active_admins = User.query.filter(User.is_active==True, User.is_admin ==True).count()
    

    if active_admins>0:
        flash('Aplication is already set-up. Nothing to do')
        return redirect(url_for('index'))
    
    # if not - create/update admin account with a new password and admin privileges, display random username
        
    user_pass = UserPass()
    user_pass.get_random_user_pasword()
    new_admin=User(name=user_pass.user , email='noone#nowhere.no',password = user_pass.hash_password(),
                    is_active = True , is_admin = True )
    db.session.add(new_admin)
    db.session.commit()
    # db.execute(''' insert into users (name, email, password, is_active, is_admin)
    #                 values (?,?,?,True,True);''',
    #                 [user_pass.user, 'noone@nowhere.no', user_pass.hash_password()])
    
    # db.commit()
    flash('User {} with password {} has been created'.format(user_pass.user, user_pass.password))
    return(redirect(url_for('index')))


@app.route('/login', methods=['GET','POST'])
def login():

    login = UserPass(session.get('user'))
    login.get_user_info()
    

    if request.method == 'GET':
        return render_template('login.html', active_menu='login', login=login)
    else:
        user_name = '' if 'user_name' not in request.form else request.form['user_name']
        user_pass = '' if 'user_pass' not in request.form else request.form['user_pass']

        login = UserPass(user_name,user_pass)
        login_record = login.login_user()

        if login_record != None:
            session['user'] = user_name
            flash('Logon succesfull, welcome {}'.format(user_name))
            return redirect(url_for('index', active_menu='home'))
        else:
            flash('Logon failed, try again')
            return render_template('login.html', active_menu='login', login=login)

@app.route('/logout')
def logout():

    if 'user' in session:
        session.pop('user', None)
        flash('You are logged out.')
    return redirect(url_for('login'))
    # return render_template('login.html', active_menu='login')


@app.route('/')
def index():

    login = UserPass(session.get('user'))
    login.get_user_info()

    return render_template('index.html', active_menu='home', login=login)

@app.route('/exchange', methods=['GET','POST'])
def exchange():
    
    login = UserPass(session.get('user'))
    login.get_user_info()

    if not login.is_valid:
        return redirect(url_for('login'))

    offer = CantorOffer()
    offer.load_offer()

    if request.method == 'GET':
        return render_template('exchange.html', active_menu='exchange', offer=offer, login=login) 
    
    else:
        amount = '100'
        if 'amount' in request.form:
                amount = request.form['amount']

        currency = 'EUR'
        if 'currency' in request.form:
            currency = request.form['currency']

        if currency in offer.denied_codes:
            flash('The currency {} cannot be accepted.'.format(currency))
        elif offer.get_by_code(currency) == 'unknow':
            flash('The selected currency is unknow and cannot be accepted.')
        else:

            new_tran = Transaction(currency =currency, amount=amount, user='admin', trans_date =date.today())
            db.session.add(new_tran)
            db.session.commit()
            # db = get_db()
            # sql_command = 'insert into transactions(currency, amount , user) values (?, ?, ?)'
            # db.execute(sql_command, [currency, amount ,'admin'])
            # db.commit()
            flash('Request to exchange {} was accepted.'.format(currency))




        return render_template('exchange_results.html', active_menu='exchange',
                               currency=currency, amount=amount,
                               currency_info=offer.get_by_code(currency),
                               login=login)
                                    

@app.route('/histroy')
def history():

    login = UserPass(session.get('user'))
    login.get_user_info()

    if not login.is_valid:
        return redirect(url_for('login'))


    transactions = Transaction.query.all()
    # db = get_db()
    # sql_command = 'select id, currency, amount, trans_date from transactions'
    # cur = db.execute(sql_command)
    # transactions = cur.fetchall()        
    

    return render_template('history.html', active_menu='history', transactions=transactions, login=login)

@app.route('/delete_transaction/<int:transaction_id>')
def delete_transaction(transaction_id):

    login = UserPass(session.get('user'))
    login.get_user_info()

    if not login.is_valid:
        return redirect(url_for('login'))
    
    del_tran = Transaction.query.filter(Transaction.id==transaction_id).first()
    db.session.delete(del_tran)
    db.session.commit()

    # db =get_db()
    # sql_statement = 'delete from transactions where id =?'
    # db.execute(sql_statement,[transaction_id])
    # db.commit()

    return redirect(url_for('history'))


@app.route('/edit_transaction/<int:transaction_id>', methods=['GET','POST'])
def edit_transaction(transaction_id):

    login = UserPass(session.get('user'))
    login.get_user_info()

    if not login.is_valid:
        return redirect(url_for('login'))

    offer = CantorOffer()
    offer.load_offer()
    # db =get_db()

    if request.method == 'GET':
        transaction = Transaction.query.filter(Transaction.id==transaction_id).first()
        # sql_statement = 'select id, currency,amount from transactions where id =?;'
        # cur = db.execute(sql_statement,[transaction_id])
        # transaction = cur.fetchone()

        if transaction == None:
            flash('No such transaction!')
            return redirect(url_for('history'))
        else:
            return render_template('edit_transaction.html',transaction=transaction, offer=offer,
                                                active_menu='history', login=login) 
    
    else:
        amount = '100'
        if 'amount' in request.form:
                amount = request.form['amount']

        currency = 'EUR'
        if 'currency' in request.form:
            currency = request.form['currency']

        if currency in offer.denied_codes:
            flash('The currency {} cannot be accepted.'.format(currency))
        elif offer.get_by_code(currency) == 'unknow':
            flash('The selected currency is unknow and cannot be accepted.')
        else:
            transaction = Transaction.query.filter(Transaction.id==transaction_id).first()
            transaction.currency = currency 
            transaction.amount = amount 
            transaction.user = 'admin' 
            transaction.trans_date  = date.today()
            db.session.commit()
            # sql_command =  '''  update transactions set 
            #                         currency=?, 
            #                         amount=?, 
            #                         user=?,
            #                         trans_date=?
            #                     where
            #                          id=?; '''
            
            # db.execute(sql_command, [currency, amount ,'admin', date.today(), transaction_id])
            # db.commit()
            flash('Transaction was updated.')

        return redirect(url_for('history'))
    

# lista wszystkich użytkowników
@app.route('/users')
def users():

    login = UserPass(session.get('user'))
    login.get_user_info()

    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))

    users = User.query.all()
    # db = get_db()
    # sql_command = 'select id, name, email, is_admin, is_active from users;'
    # cur = db.execute(sql_command)
    # users = cur.fetchall()

    return render_template('users.html',active_menu='index', users=users, login=login)


# bedzie pozwalac na zmiany is_active is_admin
@app.route('/user_status_chenge/<action>/<user_name>')
def user_status_chenge(action,user_name): 

    login = UserPass(session.get('user'))
    login.get_user_info()

    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))
    

    # if not 'user' in session:
    #     return redirect(url_for('login'))
    # login = session['user']

    # db = get_db()

    if action == 'active':
        user = User.query.filter(User.name== user_name, User.name != login.user).first()
        if user:
            user.is_active = (user.is_active + 1) % 2
            db.session.commit()
        # db.execute("""update users set is_active = (is_active + 1) % 2
        #            where name = ? and name <> ? """,
        #             [user_name,login.user])
        # db.commit()
    elif action == 'admin':
        user = User.query.filter(User.name== user_name, User.name != login.user).first()
        if user:
            user.is_admin  = (user.is_admin  + 1) % 2
            db.session.commit()
        # db.execute("""update users set is_admin = (is_admin + 1) % 2
        #            where name = ? and name <> ? """,
        #             [user_name,login.user])
        # db.commit()


    return redirect(url_for('users'))


# edycja pewnych informacji o użytkowniku
@app.route('/edit_user/<user_name>', methods=['GET','POST'])
def edit_user(user_name): 

    login = UserPass(session.get('user'))
    login.get_user_info()

    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))

    
    # db = get_db()
    # cur =db.execute('select name, email from users where name = ?',[user_name])
    # user = cur.fetchone()
    user = User.query.filter(User.name == user_name).first()
    message = None

    if user== None:
        flash('No such user')
        return  redirect(url_for('users'))
    
    if request.method == 'GET':
        return render_template('edit_user.html', active_menu='users', user=user, login=login)
    else:
        new_email  = '' if not 'email' in request.form else request.form['email']
        new_password  = '' if not 'user_pass' in request.form else request.form['user_pass']

        if new_email != user.email:
            user.email.email = new_email
            db.session.commit()
            # sql_statement = "update users set email = ? where name = ?"
            # db.execute(sql_statement, [new_email ,user_name ])
            # db.commit()
            flash('Email was changes')

        if new_password != '':
            user_pass = UserPass(user_name, new_password)
            user.password = user_pass.hash_password()
            db.session.commit()
            # sql_statement = "update users set password = ? where name = ?"
            # db.execute(sql_statement, [user_pass.hash_password(),user_name ])
            # db.commit()
            flash('Password was changes')

        return redirect(url_for('users'))




# wykasowanie użytkownika
@app.route('/user_delete/<user_name>')
def delete_user(user_name): 

    login = UserPass(session.get('user'))
    login.get_user_info()

    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))
    

    # if not 'user' in session:
    #     return redirect(url_for('login'))
    # login = session['user']

    user = User.query.filter(User.name== user_name, User.name !=login.user).first()
    if user:
        flash('User {} has been removed.'.format(user_name))
        db.session.delete(user)
        db.session.commit()

    # db=get_db()
    # sql_statement = "delete from users where name = ? and name <> ?"
    # db.execute(sql_statement, [user_name, login.user])
    # db.commit()

    return redirect(url_for('users'))


# dodawanie nowego użytkownika
@app.route('/new_user', methods=['GET','POST'])
def new_user(): 

    login = UserPass(session.get('user'))
    login.get_user_info()

    if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))

    # if not 'user' in session:
    #     return redirect(url_for('login'))
    
    # # Inicjalizacja zmiennej Login
    # login = session['user']

    # db = get_db()
    message = None
    user= {}

    if request.method == 'GET':
        return render_template('new_user.html', active_menu='users', user=user, login=login)
    else:
        user['user_name']  = '' if not 'user_name' in request.form else request.form['user_name']
        user['email']  = '' if not 'email' in request.form else request.form['email']
        user['user_pass']  = '' if not 'user_pass' in request.form else request.form['user_pass']



        is_user_name_unique = (User.query.filter(User.name ==user['user_name']).count() ==0)
        is_user_email_unique = (User.query.filter(User.name ==user['email']).count() ==0)
        # cursor = db.execute('select count(*) as cnt from users where name =?', [user['user_name']])
        # record = cursor.fetchone()
        # is_user_name_unique = (record['cnt'] == 0)

        # cursor = db.execute('select count(*) as cnt from users where email =?', [user['email']])
        # record = cursor.fetchone()
        # is_user_email_unique = (record['cnt'] == 0)



        if user['user_name']  == '':
            message = 'Name cannot be emtpy'
        elif user['email'] == '':
            message = 'email cannot be emtpy'
        elif user['user_pass'] == '':
            message = 'Password cannot be emtpy'
        elif not is_user_name_unique:
            message = 'User with the name {} already exists'.format(user['user_name'])
        elif not is_user_email_unique:
            message = 'User with the email {} already exists'.format(user['email'])


        if not message:
            user_pass = UserPass(user['user_name'], user['email'])
            password_hash = user_pass.hash_password()

            new_user = User(name=user['user_name'], email = user['email'] , password = password_hash,is_active  =True, is_admin  =False )
            db.session.add(new_user)
            db.session.commit()

            # sql_statement =  ''' insert into users (name, email, password, is_active, is_admin)
            #         values (?,?,?,True,False);'''
            # db.execute(sql_statement,[user['user_name'], user['email'], password_hash])
            # db.commit()
            flash('User {} created'.format(user['user_name']))
            return(redirect(url_for('users')))
        
        else:
            flash('Correct error: {}'.format(message))
            return render_template('new_user.html', active_menu='users', user=user, login=login)


    

if __name__ =='__main__':
    app.run()