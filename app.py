from flask import Flask, session, render_template, request, flash, redirect, url_for, jsonify
import sqlite3
import hashlib
from functools import wraps 

app = Flask(__name__)
app.secret_key = "knjhsbhgsbchbcsubucsmcksmcjvjsnvjnsjnvjndj"


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def roles_permitted(roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if 'user_id' in session and session['role'] in roles:
                return f(*args, **kwargs)
            else:
                flash(f'ERROR you need {roles} role to access this page')
                return redirect(url_for('home'))
        return wrapper
    return decorator

def get_db():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn 

def hash_password(password):
    return hashlib.sha512(password.encode('utf-8')).hexdigest()
   
def verify_password(password, password_hash):
    return hash_password(password) == password_hash

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        firstname TEXT NOT NULL,
                        lastname TEXT NOT NULL,
                        tel TEXT,
                        address TEXT,
                        role TEXT DEFAULT 'employee',
                        is_active INTEGER DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                   """)
    
    # Customers table
    cursor.execute("""
                    CREATE TABLE IF NOT EXISTS customers (
                       c_id INTEGER PRIMARY KEY AUTOINCREMENT,
                       user_id TEXT NOT NULL,
                       first_name TEXT NOT NULL,
                       last_name TEXT NOT NULL,
                       email TEXT NOT NULL,
                       tel TEXT,
                       address TEXT,
                       company TEXT,
                       country TEXT,
                       status TEXT CHECK(status IN ('Active', 'Inactive', 'Lead', 'Cancelled')) DEFAULT 'Active',
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       updated_at TIMESTAMP,
                       last_contact_date TIMESTAMP
                       )
                   """)
    
     # Interactions table 
    cursor.execute("""
                    CREATE TABLE IF NOT EXISTS interactions (
                        interaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        c_id INTEGER,
                        user_id INTEGER,
                        type TEXT,
                        interaction_date TIMESTAMP,
                        notes TEXT,
                        customer_responded TEXT,
                        created_at TIMESTAMP
                        )
                   """)
    
    # Comments table
    cursor.execute("""
                    CREATE TABLE IF NOT EXISTS comments (
                        comment_id INTEGER PRIMARY KEY AUTOINCREMENT ,
                        interaction_id INTEGER,
                        c_id INTEGER,
                        user_id INTEGER,
                        comment_text TEXT,
                        no_responce_flag TEXT,
                        created_at TIMESTAMP,
                        updated_at TIMESTAMP
                   )
                    """)
    


    conn.commit()
    conn.close()

@app.route('/')
def base():
    return render_template("base.html")

# EMPLOYEE
@app.route('/employee')
@roles_permitted(['employee'])
def employee():
    session['selected_role'] = 'employee'
    return render_template("employee.html")

@app.route('/dashboard')
@roles_permitted(['employee'])
def dashboard():
    db = get_db()
    cursor = db.cursor()

    total_customers = cursor.execute("SELECT COUNT(*) FROM customers").fetchone()[0]
    total_contacts = cursor.execute("SELECT COUNT(*) FROM interactions").fetchone()[0]
    no_responses = cursor.execute("SELECT COUNT(*) FROM interactions WHERE customer_responded IS NULL").fetchone()[0]
    active_customers = cursor.execute("SELECT COUNT(*) FROM customers WHERE status = 'Active'").fetchone()[0]

    return render_template("dashboard.html", total_customers=total_customers, total_contacts=total_contacts, no_responses=no_responses, active_customers=active_customers)

     # CUSTOMERS
@app.route('/customers')
@roles_permitted(['employee'])
def customers():
    db = get_db()
    cursor = db.cursor()
    all_customers = cursor.execute("SELECT * FROM customers").fetchall()
    return render_template('customers.html', customers=all_customers)

@app.route('/add_customer', methods =[ 'GET', 'POST' ])
@roles_permitted(['employee'])
def add_customer():
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        form = request.form 
        name = form['first_name']
        surname = form['last_name']
        email = form['email']
        tel = form['tel']
        address = form['address']
        company = form['company']
        country = form['country']
        cursor.execute("INSERT INTO customers (user_id, first_name, last_name, email, tel, address, company, country, status) VALUES (?,?,?,?,?,?,?,?,?)",
                       (session['user_id'],name, surname, email, tel, address, company, country, 'Active'))
        db.commit()
        flash("Customer added successfully", "success")
        return redirect(url_for('customers')) 
    else:
        
        return render_template('add_customer.html')
    
@app.route('/update_status', methods =['POST'])
@roles_permitted(['employee'])
def update_status():
    db = get_db()
    cursor = db.cursor()

    data = request.get_json()
    c_id = data.get('id')
    new_status = data.get('status')


    cursor.execute("UPDATE customers SET status=? WHERE c_id=?", (new_status, c_id))
    db.commit()
    db.close()

    return jsonify({'success' : True})
       
       # COMMENTS

@app.route('/comments/<int:c_id>')
@roles_permitted(['employee'])
def comments(c_id):
    db = get_db()
    cursor = db.cursor()
    all_comments = cursor.execute("SELECT * FROM comments WHERE c_id = ?", (c_id,)).fetchall()
    return render_template('comments.html', comments=all_comments, c_id=c_id)

@app.route('/add_comment/<int:c_id>', methods =(['GET','POST']))
@roles_permitted(['employee'])
def add_comment(c_id):
    db = get_db()
    cursor = db.cursor()

   
    if request.method == 'POST':
        form = request.form
        interaction_id = form.get('interaction_id', None)
        c_id = form['c_id']
        comment_text = form['comment_text']
        no_responce_flag = form.get('no_responce_flag') 
        user_id = session['user_id']

        cursor.execute("INSERT INTO comments (interaction_id, c_id, user_id, comment_text, no_responce_flag) VALUES (?, ?, ?, ?, ?)"
                       , (interaction_id, c_id, user_id, comment_text, no_responce_flag ))
        
        db.commit()
        db.close()
        flash("Comment added successfully", "success")
        return redirect(url_for('customers'))
    
    else:

        flash("Something went wrong. Please try again.", "danger")
        customer = cursor.execute("SELECT * FROM customers WHERE c_id = ?", (c_id,)).fetchone()
        return render_template('add_comment.html', customer=customer)
    
        # INTERACTIONS

@app.route('/interactions/<int:c_id>')
@roles_permitted(['employee'])
def interactions(c_id):
    db = get_db()
    cursor = db.cursor()
    all_interactions = cursor.execute("SELECT * FROM interactions WHERE c_id = ?", (c_id,)).fetchall()
    return render_template('interactions.html', interactions=all_interactions, c_id=c_id)


@app.route('/add_interaction/<int:c_id>', methods =(['GET','POST']))
@roles_permitted(['employee'])
def add_interaction(c_id):
    db = get_db()
    cursor = db.cursor()

   
    if request.method == 'POST':
        form = request.form
        type = form['type']
        notes = form['notes']
        user_id = session['user_id']
        customer_responded = form.get('customer_responded')

        cursor.execute(" INSERT INTO interactions (c_id, user_id, type, notes, customer_responded) VALUES (?, ?, ?, ?, ?)"
                        , (c_id, user_id, type, notes, customer_responded))
        
        db.commit()
        db.close()
        flash("Interaction added successfully", "success")
        return redirect(url_for('customers'))
    
    else:

        flash("Something went wrong. Please try again.", "danger")
        customer = cursor.execute("SELECT * FROM customers WHERE c_id = ?", (c_id,)).fetchone()
        return render_template('add_interaction.html', customer=customer)

# ADMIN

@app.route('/admin')
@roles_permitted(['admin'])
def admin():
    session['selected_role'] = 'admin'
    return render_template("admin.html")

@app.route('/crud_users')
@roles_permitted(['admin'])
def crud_users():
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT id, username, firstname, lastname, role, email, tel, address, is_active FROM users")

    users = cursor.fetchall()
    return render_template("crud_users.html", users=users)

@app.route('/add_user', methods=['GET', 'POST'])
@roles_permitted(['admin'])
def add_user():
    username = ''
    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        username = request.form['username']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        password = request.form['password']
        password2 = request.form['password2']
        email = request.form['email']
        tel = request.form['tel']
        address = request.form['address']
        role = request.form.get('role')

        if password != password2:
            flash("ERROR: Passwords do not match", "danger")
            return redirect(url_for('add_user'))
        else:
            user = cursor.execute("SELECT * FROM users WHERE username=? OR email=?", (username, email)).fetchone()
            if user:
                flash("ERROR: Username or email already exists", "danger")
                return redirect(url_for('add_user'))
            else:
                 hashed_password = hash_password(password)
                 cursor.execute("INSERT INTO users (username, password_hash, email, firstname, lastname, tel, address, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                (username, hashed_password, email, firstname, lastname, tel, address, role))
                 db.commit()
                 flash("User added successfully", "success")
                 return redirect(url_for('crud_users'))
                  
    return render_template('add_user.html')   

@app.route('/edit_user/<int:id>', methods=['GET', 'POST'])
@roles_permitted(['admin'])
def edit_user(id):
    db = get_db()
    cursor = db.cursor()
    user = cursor.execute("SELECT * FROM users WHERE id=?", (id,)).fetchone()

    if request.method == 'POST':
        username = request.form['username']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        tel = request.form['tel']
        address = request.form['address']
        role = request.form.get('role')

        cursor.execute("UPDATE users SET username=?, firstname=?, lastname=?, email=?, tel=?, address=?, role=? WHERE id=?",
                       (username, firstname, lastname, email, tel, address, role, id))
        db.commit()
        cursor.close()
        flash("User updated successfully", "success")
        return redirect(url_for('crud_users'))
    

    cursor.execute("SELECT id, username, email, firstname, lastname, tel, address, role FROM users")
    user = cursor.fetchall()
    user = next((u for u in user if u['id'] == id), None)
    flash("Something went wrong. Please try again.", "danger")
    return render_template("edit_user.html", user=user)


@app.route('/disable_user', methods=['POST'])
@roles_permitted(['admin'])
def disable_user():
    data = request.get_json()
    id = data['id']
    status = data['status']
    
    is_active = 1 if status == 'Active' else 0

    db = get_db()
    cursor = db.cursor()

    cursor.execute("UPDATE users SET is_active = ? WHERE id = ?", (is_active, id))
    db.commit()
    flash("User status updated", "success")
    return jsonify(success=True)


# MANAGER

@app.route('/manager')
@roles_permitted(['manager'])
def manager():
   session['selected_role'] = 'manager'
   return render_template("manager.html")

@app.route('/con_per')  # contacts per employee
@roles_permitted(['manager'])
def con_per():
    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
                   SELECT u.firstname, u.lastname, COUNT(interaction_id) AS total_contacts
                   FROM users u
                   LEFT JOIN interactions ON u.id = user_id
                   WHERE u.role = 'employee'
                   GROUP BY u.id
                   """)
    
    contacts = cursor.fetchall()
    return render_template("con_per.html", contacts= contacts)

@app.route('/cus_with_no_con') # customers with no contact 
@roles_permitted(['manager'])
def cus_with_no_con(): 
    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
                   SELECT c.first_name, c.last_name
                   FROM customers c
                   LEFT JOIN interactions ON c.c_id = interactions.c_id
                   WHERE interactions.c_id IS NULL
                   ORDER BY c.first_name
                  """)
    
    customers = cursor.fetchall()
    return render_template('cus_with_no_con.html', customers=customers)

@app.route('/cus_nev_res') # customers who never responded
@roles_permitted(['manager'])
def cus_nev_res():
    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
                   SELECT c.first_name, c.last_name, COUNT(CASE WHEN customer_responded IS NOT NULL THEN 1 END ) AS no_response_count
                   FROM customers c
                   LEFT JOIN interactions ON c.c_id = interactions.c_id
                   GROUP BY c.c_id
                   HAVING no_response_count > 0
                   ORDER BY no_response_count
                   """)
    
    customers = cursor.fetchall()
    return render_template("cus_nev_res.html", customers=customers)

@app.route('/cus_per_cat') # customers per category
@roles_permitted(['manager'])
def cus_per_cat():
    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
                   SELECT first_name, last_name, status AS category
                   FROM customers
                   ORDER BY status
                   """)
    
    customers = cursor.fetchall()
    return render_template("cus_per_cat.html", customers=customers)
      
      # PROFILE

@app.route('/profile')
@login_required
def profile():
    db = get_db()
    cursor = db.cursor()

    user = cursor.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()

    role = session.get('selected_role')
    base_template = F"base_{role}.html" 

    return render_template("profile.html", user=user, base_template=base_template)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    db = get_db()
    cursor = db.cursor()

    role = session.get('selected_role')
    base_template = F"base_{role}.html" 

    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        tel = request.form['tel']
        address = request.form['address']

        cursor.execute("UPDATE users SET firstname=?, lastname=?, email=?, tel=?, address=? WHERE id=?",
                       (firstname, lastname, email, tel, address, session['user_id']))
        
        db.commit()
        flash("Profile updated successfully", "success")
        return redirect(url_for('profile'))
    
    else:
        flash("Something went wrong. Please try again.", "danger")
        user = cursor.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        return render_template('edit_profile.html', user=user, base_template=base_template)

@app.route('/change_password', methods=['GET', 'POST'])          
@login_required
def change_password():
    db = get_db()
    cursor = db.cursor()

    role = session.get('selected_role')
    base_template = F"base_{role}.html" 
    
    user = cursor.execute("SELECT password_hash FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    
    if request.method == 'POST':
        current = request.form['current_password']
        new = request.form['new_password']
        confirm = request.form['confirm_password']

        if not verify_password(current, user['password_hash']):
            flash("Current password is incorrect", "danger")
            return redirect(url_for('change_password'))
        elif new != confirm:
            flash("Passwords do not match", "danger")
            return redirect(url_for('change_password'))
        else:
            new_hash = hash_password(new)
            cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", 
                (new_hash, session['user_id'],))
            
            db.commit()
            db.close()

            flash("Password updated successfully!", "success")
            return redirect(url_for('profile'))
        
    return render_template('change_password.html', user=user, base_template=base_template)    
        


@app.route('/home')
@login_required
def home():
    conn = get_db()
    cursor = conn.cursor()

    user = cursor.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()

    return render_template('home.html', user=user)

@app.route('/login', methods=[ 'GET', 'POST'])
def login():
    username = ''
    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        form = request.form
        username = request.form['username']
        password = request.form['password']
        user = cursor.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

        
        if not user:
            flash("Invalid username or password")
            return redirect(url_for('login'))
        
        if user['is_active'] == 0:
            flash("Your account is disabled.")
            return redirect(url_for('login'))
        
        if not verify_password(password, user['password_hash']):
            flash("Invalid username or password")
            return redirect(url_for('login'))
        
        session['user_id'] = user['id']
        session['role'] = user['role']
        flash("Logged in succesfully", "success")
        return redirect(url_for('home')) 

    return render_template('login.html')        


@app.route('/register', methods=['GET', 'POST'])
def register():
    username = ''
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password2 = request.form['password2']
        email = request.form['email']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        tel = request.form['tel']
        address = request.form['address']
        role = request.form['role']

        if password != password2:
            flash("ERROR: Passwords do not match")
            return redirect(url_for('register'))
        else:
            user = cursor.execute("SELECT * FROM users WHERE username=? OR email=?", (username, email)).fetchone()
            if user:
                flash("ERROR: Username or email already exists")
                return redirect(url_for('register'))
            else:
                 hashed_password = hash_password(password)
                 cursor.execute("INSERT INTO users (username, password_hash, email, firstname, lastname, tel, address, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                (username, hashed_password, email, firstname, lastname, tel, address, role))
                 db.commit()
                 flash("Account created successfully. Please login.", "success")
                 return redirect(url_for('login'))

    return render_template('register.html')  

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login') 

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5001)