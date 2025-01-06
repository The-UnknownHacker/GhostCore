from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from functools import wraps
import sqlite3
import hashlib
from datetime import datetime, timedelta
import json
import requests
import os
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
import base64
import markdown2
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import secrets

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a secure secret key

def init_db():
    conn = sqlite3.connect('ghostcore.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS organizations
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL UNIQUE,
                  display_name TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT NOT NULL UNIQUE,
                  email TEXT NOT NULL UNIQUE,
                  password_hash TEXT NOT NULL,
                  org_id INTEGER,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (org_id) REFERENCES organizations(id))''')
    
    c.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
    
    c.execute('''CREATE TABLE IF NOT EXISTS services
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  description TEXT,
                  github_url TEXT,
                  demo_url TEXT,
                  org_id INTEGER NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (org_id) REFERENCES organizations(id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS statistics
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  service_id INTEGER,
                  views INTEGER DEFAULT 0,
                  stars INTEGER DEFAULT 0,
                  last_updated TIMESTAMP,
                  FOREIGN KEY (service_id) REFERENCES services(id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS changelog
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  service_id INTEGER,
                  version TEXT,
                  changes TEXT,
                  release_date TIMESTAMP,
                  FOREIGN KEY (service_id) REFERENCES services(id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS api_tokens
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  token TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users(id))''')
    
    conn.commit()
    conn.close()

init_db()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        org_name = request.form['org_name']
        org_display_name = request.form['org_display_name']
        
        conn = sqlite3.connect('ghostcore.db')
        c = conn.cursor()
        
        try:
            c.execute('INSERT INTO organizations (name, display_name, created_at) VALUES (?, ?, ?)',
                     (org_name, org_display_name, datetime.now()))
            org_id = c.lastrowid
            
            password_hash = generate_password_hash(password)
            c.execute('INSERT INTO users (username, email, password_hash, org_id, created_at) VALUES (?, ?, ?, ?, ?)',
                     (username, email, password_hash, org_id, datetime.now()))
            
            conn.commit()
            flash('Account created successfully!', 'success')
            return redirect(url_for('login'))
            
        except sqlite3.IntegrityError:
            flash('Username, email, or organization name already exists!', 'error')
        finally:
            conn.close()
            
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        print(f"Login attempt for username: {username}")  
        
        conn = sqlite3.connect('ghostcore.db')
        c = conn.cursor()
        
        try:
            c.execute('''SELECT u.*, o.name as org_name, o.display_name as org_display_name 
                        FROM users u 
                        JOIN organizations o ON u.org_id = o.id 
                        WHERE u.username=?''', (username,))
            user = c.fetchone()
            
            print(f"Database returned user: {user}") 
            
            if user:
                is_valid = check_password_hash(user[3], password)
                print(f"Password valid: {is_valid}")  
            
            
            if user is None:
                flash('Invalid username or password', 'error')
                return render_template('login.html')
            
            if check_password_hash(user[3], password):  
                session['user_id'] = user[0]
                session['org_id'] = user[4]
                session['org_name'] = user[6]
                session['org_display_name'] = user[7]
                
                flash('Successfully logged in!', 'success')
                return redirect(url_for('org_dashboard', org_name=user[6]))
            else:
                flash('Invalid username or password', 'error')
                
        except Exception as e:
            print(f"Login error: {str(e)}")  # For debugging
            flash('An error occurred during login', 'error')
        finally:
            conn.close()
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Successfully logged out!', 'success')
    return redirect(url_for('index'))

# Organization-specific routes
@app.route('/<org_name>/dashboard')
def org_dashboard(org_name):
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    if session['org_name'] != org_name:
        flash('Access denied!', 'error')
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('ghostcore.db')
    c = conn.cursor()
    
    # Get or create API token
    c.execute('SELECT token FROM api_tokens WHERE user_id = ?', (session['user_id'],))
    token_row = c.fetchone()
    
    if not token_row:
        token = secrets.token_urlsafe(32)
        c.execute('INSERT INTO api_tokens (user_id, token) VALUES (?, ?)',
                 (session['user_id'], token))
        conn.commit()
    else:
        token = token_row[0]
    
    # Get services with their statistics and README content
    c.execute('''
        SELECT s.*, st.stars, st.views 
        FROM services s
        LEFT JOIN statistics st ON s.id = st.service_id
        WHERE s.org_id = ?
    ''', (session['org_id'],))
    services = c.fetchall()
    
    # Get README content for each service
    services_with_readme = []
    for service in services:
        owner, repo = extract_github_info(service[3])  # service[3] is github_url
        readme_html = get_github_readme(owner, repo) if owner and repo else None
        services_with_readme.append({
            'id': service[0],
            'name': service[1],
            'description': service[2],
            'github_url': service[3],
            'demo_url': service[4],
            'stars': service[7],
            'views': service[8],
            'readme': readme_html
        })
    
    conn.close()
    return render_template('org_dashboard.html', 
                         services=services_with_readme,
                         api_token=token)

@app.route('/<org_name>/add_service', methods=['GET', 'POST'])
def org_add_service(org_name):
    if not session.get('user_id') or session['org_name'] != org_name:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        github_url = request.form['github_url']
        demo_url = request.form['demo_url']
        
        conn = sqlite3.connect('ghostcore.db')
        c = conn.cursor()
        
        try:
            c.execute('''INSERT INTO services 
                        (name, description, github_url, demo_url, org_id, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)''',
                     (name, description, github_url, demo_url, 
                      session['org_id'], datetime.now()))
            conn.commit()
            flash('Service added successfully!', 'success')
            
        except Exception as e:
            conn.rollback()
            flash(f'Error adding service: {str(e)}', 'error')
        finally:
            conn.close()
        
        return redirect(url_for('org_dashboard', org_name=org_name))
    
    return render_template('org_add_service.html')

@app.route('/admin')
def admin_panel():
    if not session.get('user_id'):
        flash('Access denied!', 'error')
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('ghostcore.db')
    c = conn.cursor()
    
    # Check if user is admin
    c.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    if not user or user[0] != 'admin':
        flash('Access denied!', 'error')
        conn.close()
        return redirect(url_for('index'))
    
    # Get all organizations with their service and user counts
    c.execute('''
        SELECT 
            o.id,
            o.name,
            o.display_name,
            o.created_at,
            COUNT(DISTINCT s.id) as service_count,
            COUNT(DISTINCT u.id) as user_count
        FROM organizations o
        LEFT JOIN services s ON o.id = s.org_id
        LEFT JOIN users u ON o.id = u.org_id
        GROUP BY o.id
        ORDER BY o.created_at DESC
    ''')
    organizations = c.fetchall()
    
    # Get all users with their organization names
    c.execute('''
        SELECT 
            u.id,
            u.username,
            u.email,
            u.created_at,
            o.display_name as org_name
        FROM users u
        JOIN organizations o ON u.org_id = o.id
        ORDER BY u.created_at DESC
    ''')
    users = c.fetchall()
    
    # Get all services with their organization names
    c.execute('''
        SELECT 
            s.id,
            s.name,
            s.description,
            s.github_url,
            s.created_at,
            o.display_name as org_name,
            st.views,
            st.stars
        FROM services s
        JOIN organizations o ON s.org_id = o.id
        LEFT JOIN statistics st ON s.id = st.service_id
        ORDER BY s.created_at DESC
    ''')
    services = c.fetchall()
    
    conn.close()
    return render_template('admin_panel.html', 
                         organizations=organizations,
                         users=users,
                         services=services)

@app.route('/admin/delete_org/<int:org_id>')
def admin_delete_org(org_id):
    if not session.get('user_id') or session.get('username') != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('ghostcore.db')
    c = conn.cursor()
    
    # Don't allow deleting the default organization
    c.execute('SELECT name FROM organizations WHERE id = ?', (org_id,))
    org = c.fetchone()
    if org and org[0] == 'default':
        flash('Cannot delete the default organization!', 'error')
        return redirect(url_for('admin_panel'))
    
    # Delete the organization and all its services
    c.execute('DELETE FROM services WHERE org_id = ?', (org_id,))
    c.execute('DELETE FROM users WHERE org_id = ?', (org_id,))
    c.execute('DELETE FROM organizations WHERE id = ?', (org_id,))
    
    conn.commit()
    conn.close()
    
    flash('Organization deleted successfully!', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_user/<int:user_id>')
def admin_delete_user(user_id):
    if not session.get('user_id') or session.get('username') != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('ghostcore.db')
    c = conn.cursor()
    
    # Don't allow deleting the admin user
    c.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    if user and user[0] == 'admin':
        flash('Cannot delete the admin user!', 'error')
        return redirect(url_for('admin_panel'))
    
    c.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/add_service', methods=['POST'])
@login_required
def add_service():
    name = request.form['name']
    description = request.form['description']
    github_url = request.form['github_url']
    demo_url = request.form['demo_url']
    
    conn = sqlite3.connect('ghostcore.db')
    c = conn.cursor()
    
    try:
        # Insert service
        c.execute('''INSERT INTO services (name, description, github_url, demo_url, created_at)
                     VALUES (?, ?, ?, ?, ?)''',
                  (name, description, github_url, demo_url, datetime.now()))
        
        service_id = c.lastrowid
        
        # Initialize statistics
        c.execute('''INSERT INTO statistics (service_id, views, stars, last_updated)
                     VALUES (?, 0, 0, ?)''',
                  (service_id, datetime.now()))
        
        # Get initial GitHub stats
        owner, repo = extract_github_info(github_url)
        if owner and repo:
            headers = {'Authorization': f'token {GITHUB_TOKEN}'}
            url = f'https://api.github.com/repos/{owner}/{repo}'
            
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                stars = data['stargazers_count']
                c.execute('UPDATE statistics SET stars = ? WHERE service_id = ?',
                         (stars, service_id))
        
        conn.commit()
        flash('Service added successfully!', 'success')
        
    except Exception as e:
        conn.rollback()
        flash(f'Error adding service: {str(e)}', 'error')
        
    finally:
        conn.close()
    
    return redirect(url_for('admin'))

@app.route('/delete_service/<int:id>')
@login_required
def delete_service(id):
    conn = sqlite3.connect('ghostcore.db')
    c = conn.cursor()
    c.execute('DELETE FROM services WHERE id=?', (id,))
    conn.commit()
    conn.close()
    
    flash('Service deleted successfully!', 'success')
    return redirect(url_for('admin'))

@app.route('/service/<int:id>')
def service_detail(id):
    conn = sqlite3.connect('ghostcore.db')
    c = conn.cursor()
    
    try:
        c.execute('''
            SELECT s.*, st.views, st.stars 
            FROM services s
            LEFT JOIN statistics st ON s.id = st.service_id
            WHERE s.id = ?
        ''', (id,))
        service = c.fetchone()
        
        if not service:
            flash('Service not found', 'error')
            return redirect(url_for('index'))
            
        c.execute('SELECT * FROM statistics WHERE service_id = ?', (id,))
        stats = c.fetchone() or [0, 0, 0, 0, None]  # Default values if no stats
        
        owner, repo = extract_github_info(service[3])
        readme_html = get_github_readme(owner, repo) if owner and repo else None
        
        c.execute('SELECT * FROM changelog WHERE service_id = ? ORDER BY release_date DESC', (id,))
        changelog = c.fetchall()
        
        return render_template('service_detail.html',
                             service=service,
                             stats=stats,
                             readme_html=readme_html,
                             changelog=changelog)
    finally:
        conn.close()

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    service_id = request.form['service_id']
    name = request.form['name']
    email = request.form['email']
    message = request.form['message']
    rating = request.form['rating']
    
    conn = sqlite3.connect('ghostcore.db')
    c = conn.cursor()
    c.execute('''INSERT INTO feedback (service_id, name, email, message, rating, created_at)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (service_id, name, email, message, rating, datetime.now()))
    conn.commit()
    conn.close()
    
    flash('Thank you for your feedback!', 'success')
    return redirect(url_for('service_detail', id=service_id))

@app.route('/add_changelog', methods=['POST'])
def add_changelog():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    service_id = request.form.get('service_id')
    version = request.form.get('version')
    changes = request.form.get('changes')
    
    conn = sqlite3.connect('ghostcore.db')
    c = conn.cursor()
    
    try:
        # Verify user owns the service
        c.execute('''SELECT s.* FROM services s 
                    WHERE s.id = ? AND s.org_id = ?''', 
                 (service_id, session['org_id']))
        service = c.fetchone()
        
        if not service:
            flash('Access denied!', 'error')
            return redirect(url_for('index'))
        
        # Add changelog entry
        c.execute('''INSERT INTO changelog 
                    (service_id, version, changes, release_date)
                    VALUES (?, ?, ?, ?)''',
                 (service_id, version, changes, datetime.now()))
        conn.commit()
        
        flash('Version added successfully!', 'success')
        return redirect(url_for('service_detail', id=service_id))
        
    except Exception as e:
        flash(f'Error adding version: {str(e)}', 'error')
        return redirect(url_for('service_detail', id=service_id))
        
    finally:
        conn.close()

@app.route('/update_github_stats')
@login_required
def update_github_stats():
    conn = sqlite3.connect('ghostcore.db')
    c = conn.cursor()
    
    try:
        print("\n=== Starting GitHub Stats Update ===")
        # First, ensure all services have statistics entries
        c.execute('''INSERT OR IGNORE INTO statistics (service_id, views, stars, last_updated)
                     SELECT id, 0, 0, CURRENT_TIMESTAMP
                     FROM services WHERE id NOT IN (SELECT service_id FROM statistics)''')
        
        # Get all services
        c.execute('SELECT id, github_url FROM services')
        services = c.fetchall()
        print(f"Found {len(services)} services to update")
        
        success_count = 0
        error_count = 0
        
        for service in services:
            service_id, github_url = service
            print(f"\nProcessing service ID {service_id} with URL: {github_url}")
            
            owner, repo = extract_github_info(github_url)
            if owner and repo:
                url = f'https://api.github.com/repos/{owner}/{repo}'
                print(f"Making request to: {url}")
                
                try:
                    response = requests.get(url, headers=GITHUB_HEADERS, timeout=10)
                    print(f"Response status: {response.status_code}")
                    
                    if response.status_code == 200:
                        data = response.json()
                        stars = data.get('stargazers_count', 0)
                        print(f"Stars found: {stars}")
                        
                        # Update statistics
                        c.execute('''UPDATE statistics 
                                   SET stars = ?, last_updated = CURRENT_TIMESTAMP 
                                   WHERE service_id = ?''',
                                (stars, service_id))
                        print(f"Rows updated: {c.rowcount}")
                        
                        if c.rowcount == 0:  # If no row was updated, insert one
                            c.execute('''INSERT INTO statistics (service_id, stars, views, last_updated)
                                       VALUES (?, ?, 0, CURRENT_TIMESTAMP)''',
                                    (service_id, stars))
                            print(f"Inserted new statistics row for service {service_id}")
                        
                        success_count += 1
                        conn.commit()  # Commit after each successful update
                    else:
                        print(f"Error response: {response.text}")
                        error_count += 1
                        
                except Exception as e:
                    print(f"Exception occurred: {str(e)}")
                    error_count += 1
                    continue
            else:
                print(f"Could not extract owner/repo from URL: {github_url}")
                error_count += 1
        
        if error_count > 0:
            flash(f'Updated {success_count} services, but encountered {error_count} errors. Check the console for details.', 'warning')
        else:
            flash(f'Successfully updated {success_count} services!', 'success')
            
    except Exception as e:
        print(f"Database error: {str(e)}")
        flash('An error occurred while updating statistics.', 'error')
        
    finally:
        conn.close()
    
    return redirect(url_for('admin'))

@app.route('/api/services')
def api_services():
    conn = sqlite3.connect('ghostcore.db')
    c = conn.cursor()
    c.execute('''SELECT s.*, st.views, st.stars 
                 FROM services s 
                 LEFT JOIN statistics st ON s.id = st.service_id''')
    services = c.fetchall()
    conn.close()
    
    return jsonify([{
        'id': s[0],
        'name': s[1],
        'description': s[2],
        'github_url': s[3],
        'demo_url': s[4],
        'created_at': s[5],
        'views': s[6] or 0,
        'stars': s[7] or 0
    } for s in services])

@app.route('/search')
def search():
    query = request.args.get('q', '').lower()
    conn = sqlite3.connect('ghostcore.db')
    c = conn.cursor()
    c.execute('''SELECT * FROM services 
                 WHERE LOWER(name) LIKE ? OR LOWER(description) LIKE ?''',
              (f'%{query}%', f'%{query}%'))
    services = c.fetchall()
    conn.close()
    return render_template('search.html', services=services, query=query)

@app.route('/service/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_service(id):
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        github_url = request.form['github_url']
        demo_url = request.form['demo_url']
        
        conn = sqlite3.connect('ghostcore.db')
        c = conn.cursor()
        c.execute('''UPDATE services 
                     SET name=?, description=?, github_url=?, demo_url=?
                     WHERE id=?''',
                  (name, description, github_url, demo_url, id))
        conn.commit()
        conn.close()
        
        flash('Service updated successfully!', 'success')
        return redirect(url_for('service_detail', id=id))
    
    conn = sqlite3.connect('ghostcore.db')
    c = conn.cursor()
    c.execute('SELECT * FROM services WHERE id=?', (id,))
    service = c.fetchone()
    conn.close()
    
    return render_template('edit_service.html', service=service)

@app.route('/stats')
def stats():
    conn = sqlite3.connect('ghostcore.db')
    c = conn.cursor()
    
    # Check when was the last update
    c.execute('SELECT MAX(last_updated) FROM statistics')
    last_update = c.fetchone()[0]
    
    # Only update if more than 5 minutes have passed
    should_update = True
    if last_update:
        try:
            # Try parsing with microseconds
            last_update = datetime.strptime(last_update, '%Y-%m-%d %H:%M:%S.%f')
        except ValueError:
            try:
                # Try parsing without microseconds
                last_update = datetime.strptime(last_update, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                should_update = True
                print(f"Could not parse timestamp: {last_update}")

        if datetime.now() - last_update < timedelta(minutes=5):
            should_update = False
    
    # Update GitHub stats if needed
    if should_update:
        try:
            # First, clear existing stats to prevent accumulation its a bigger issue than you think
            c.execute('DELETE FROM statistics')
            
            c.execute('SELECT id, github_url FROM services')
            services = c.fetchall()
            
            for service in services:
                service_id, github_url = service
                owner, repo = extract_github_info(github_url)
                if owner and repo:
                    url = f'https://api.github.com/repos/{owner}/{repo}'
                    try:
                        response = requests.get(url, headers=GITHUB_HEADERS, timeout=10)
                        if response.status_code == 200:
                            data = response.json()
                            stars = data.get('stargazers_count', 0)
                            c.execute('''INSERT INTO statistics 
                                        (service_id, stars, last_updated)
                                        VALUES (?, ?, CURRENT_TIMESTAMP)''',
                                     (service_id, stars))
                    except Exception as e:
                        print(f"Error updating stats for {github_url}: {str(e)}")
            conn.commit()
        except Exception as e:
            print(f"Error updating GitHub stats: {str(e)}")
    
    # Get total services
    c.execute('SELECT COUNT(*) FROM services')
    total_services = c.fetchone()[0]
    
    # Get total stars and views
    c.execute('SELECT SUM(stars) as total_stars, SUM(views) as total_views FROM statistics')
    stats = c.fetchone()
    total_stars = stats[0] or 0
    total_views = stats[1] or 0
    
    # Get top services by stars
    c.execute('''SELECT s.name, s.github_url, st.stars, st.views 
                 FROM services s 
                 JOIN statistics st ON s.id = st.service_id 
                 ORDER BY st.stars DESC LIMIT 5''')
    top_services = c.fetchall()
    
    # Get monthly stats
    c.execute('''SELECT strftime('%Y-%m', created_at) as month, COUNT(*) 
                 FROM services 
                 GROUP BY month 
                 ORDER BY month DESC LIMIT 12''')
    monthly_growth = c.fetchall()
    
    conn.close()
    
    return render_template('stats.html', 
                         total_services=total_services,
                         total_stars=total_stars,
                         total_views=total_views,
                         top_services=top_services,
                         monthly_growth=monthly_growth)

# Add these configurations
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN', 'your-github-token-here')
GITHUB_HEADERS = {
    'Authorization': f'token {GITHUB_TOKEN}',
    'Accept': 'application/vnd.github.v3+json',
    'X-GitHub-Api-Version': '2022-11-28'
}
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Add this function to extract GitHub info
def extract_github_info(github_url):
    if not github_url:
        return None, None
        
    try:
        # Clean the URL
        github_url = github_url.strip().rstrip('/')
        
        # Handle different URL formats
        if 'github.com' not in github_url:
            return None, None
            
        if github_url.startswith('git@'):
            path = github_url.split('github.com:')[1]
        else:
            parsed = urlparse(github_url)
            path = parsed.path.lstrip('/')
            
        path = path.replace('.git', '')
        
        parts = path.split('/')
        if len(parts) >= 2:
            owner, repo = parts[0], parts[1]
            print(f"Extracted owner: {owner}, repo: {repo} from URL: {github_url}")
            return owner, repo
            
    except Exception as e:
        print(f"Error parsing GitHub URL '{github_url}': {str(e)}")
    return None, None

@app.route('/test_github')
@login_required
def test_github():
    test_repo = "CyberZenDev/GhostAI"
    owner, repo = test_repo.split('/')
    
    url = f'https://api.github.com/repos/{owner}/{repo}'
    try:
        response = requests.get(url, headers=GITHUB_HEADERS, timeout=10)
        return jsonify({
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content': response.json() if response.status_code == 200 else response.text,
            'token_used': GITHUB_TOKEN[:10] + '...',  # Show first 10 chars of token
            'url': url
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'token_used': GITHUB_TOKEN[:10] + '...',
            'url': url
        })

@app.route('/debug_stats')
@login_required
def debug_stats():
    conn = sqlite3.connect('ghostcore.db')
    c = conn.cursor()
    
    # Get all services with their stats
    c.execute('''
        SELECT 
            s.id,
            s.name,
            s.github_url,
            st.stars,
            st.views,
            st.last_updated
        FROM services s
        LEFT JOIN statistics st ON s.id = st.service_id
    ''')
    
    results = c.fetchall()
    conn.close()
    
    # Format the data for display
    debug_data = [{
        'id': r[0],
        'name': r[1],
        'github_url': r[2],
        'stars': r[3],
        'views': r[4],
        'last_updated': r[5]
    } for r in results]
    
    return jsonify(debug_data)

# Add this function to get README content
def get_github_readme(owner, repo):
    try:
        # Try to get the README
        url = f'https://api.github.com/repos/{owner}/{repo}/readme'
        response = requests.get(url, headers=GITHUB_HEADERS)
        if response.status_code == 200:
            data = response.json()
            # Decode content from base64
            content = base64.b64decode(data['content']).decode('utf-8')
            # Convert markdown to HTML
            html_content = markdown2.markdown(content, extras=['fenced-code-blocks', 'tables'])
            return html_content
        return None
    except Exception as e:
        print(f"Error fetching README: {str(e)}")
        return None

@app.route('/organizations')
def organizations():
    conn = sqlite3.connect('ghostcore.db')
    c = conn.cursor()
    
    # Get organizations with their service counts
    c.execute('''
        SELECT o.*, COUNT(s.id) as service_count
        FROM organizations o
        LEFT JOIN services s ON o.id = s.org_id
        GROUP BY o.id
    ''')
    
    orgs = [{'id': r[0], 'name': r[1], 'display_name': r[2], 'service_count': r[4]} 
            for r in c.fetchall()]
    
    conn.close()
    return render_template('organizations.html', organizations=orgs)

@app.route('/org/<org_name>/services')
def org_services(org_name):
    conn = sqlite3.connect('ghostcore.db')
    c = conn.cursor()
    
    # Get organization info
    c.execute('SELECT * FROM organizations WHERE name = ?', (org_name,))
    org = c.fetchone()
    
    if not org:
        flash('Organization not found!', 'error')
        return redirect(url_for('organizations'))
    
    # Get organization's services with stats
    c.execute('''
        SELECT s.*, st.stars, st.views 
        FROM services s
        LEFT JOIN statistics st ON s.id = st.service_id
        WHERE s.org_id = ?
    ''', (org[0],))
    services = c.fetchall()
    
    # Get README content for each service
    services_with_readme = []
    for service in services:
        owner, repo = extract_github_info(service[3])  # Assuming service[3] is github_url
        readme_html = get_github_readme(owner, repo) if owner and repo else None
        service_dict = {
            'id': service[0],
            'name': service[1],
            'description': service[2],
            'github_url': service[3],
            'demo_url': service[4],
            'readme': readme_html,
            'stars': service[7] or 0,
            'views': service[8] or 0
        }
        services_with_readme.append(service_dict)
    
    conn.close()
    return render_template('org_services.html', org=org, services=services_with_readme)

@app.route('/docs')
def docs():
    return render_template('docs.html')

# Secret key for JWT
JWT_SECRET = 'your-secret-key' 

# API Authentication decorator
def api_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            token = token.split(' ')[1]  
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            current_user = data['user_id']
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# API Authentication endpoint
@app.route('/api/auth', methods=['POST'])
def api_auth():
    auth = request.get_json()
    
    if not auth or not auth.get('username') or not auth.get('password'):
        return jsonify({'message': 'Authentication required'}), 401
    
    conn = sqlite3.connect('ghostcore.db')
    c = conn.cursor()
    
    try:
        c.execute('SELECT * FROM users WHERE username = ?', (auth['username'],))
        user = c.fetchone()
        
        if not user or not check_password_hash(user[3], auth['password']):
            return jsonify({'message': 'Invalid credentials'}), 401
        
        # Get or create API token
        c.execute('SELECT token FROM api_tokens WHERE user_id = ?', (user[0],))
        token_row = c.fetchone()
        
        if not token_row:
            token = secrets.token_urlsafe(32)
            c.execute('INSERT INTO api_tokens (user_id, token) VALUES (?, ?)',
                     (user[0], token))
            conn.commit()
        else:
            token = token_row[0]
        
        return jsonify({
            'token': token,
            'expires_in': None  
        })
        
    finally:
        conn.close()

# API Endpoints
@app.route('/api/services', methods=['GET'])
@api_token_required
def api_get_services(current_user):
    conn = sqlite3.connect('ghostcore.db')
    c = conn.cursor()
    
    try:
        c.execute('''
            SELECT s.*, st.views, st.stars, o.name as org_name 
            FROM services s
            LEFT JOIN statistics st ON s.id = st.service_id
            LEFT JOIN organizations o ON s.org_id = o.id
        ''')
        services = c.fetchall()
        
        return jsonify([{
            'id': s[0],
            'name': s[1],
            'description': s[2],
            'github_url': s[3],
            'demo_url': s[4],
            'organization': s[8],
            'views': s[6] or 0,
            'stars': s[7] or 0,
            'created_at': s[5]
        } for s in services])
        
    finally:
        conn.close()

@app.route('/api/services/<int:id>', methods=['GET'])
@api_token_required
def api_get_service(current_user, id):
    conn = sqlite3.connect('ghostcore.db')
    c = conn.cursor()
    
    try:
        c.execute('''
            SELECT s.*, st.views, st.stars, o.name as org_name 
            FROM services s
            LEFT JOIN statistics st ON s.id = st.service_id
            LEFT JOIN organizations o ON s.org_id = o.id
            WHERE s.id = ?
        ''', (id,))
        service = c.fetchone()
        
        if not service:
            return jsonify({'message': 'Service not found'}), 404
        
        # Get README content
        owner, repo = extract_github_info(service[3])
        readme_html = get_github_readme(owner, repo) if owner and repo else None
        
        return jsonify({
            'id': service[0],
            'name': service[1],
            'description': service[2],
            'github_url': service[3],
            'demo_url': service[4],
            'organization': service[8],
            'views': service[6] or 0,
            'stars': service[7] or 0,
            'created_at': service[5],
            'readme': readme_html
        })
        
    finally:
        conn.close()

@app.route('/api/organizations', methods=['GET'])
@api_token_required
def api_get_organizations(current_user):
    conn = sqlite3.connect('ghostcore.db')
    c = conn.cursor()
    
    try:
        c.execute('''
            SELECT o.*, COUNT(s.id) as service_count
            FROM organizations o
            LEFT JOIN services s ON o.id = s.org_id
            GROUP BY o.id
        ''')
        orgs = c.fetchall()
        
        return jsonify([{
            'id': org[0],
            'name': org[1],
            'display_name': org[2],
            'service_count': org[4],
            'created_at': org[3]
        } for org in orgs])
        
    finally:
        conn.close()

@app.route('/regenerate_token', methods=['POST'])
def regenerate_token():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('ghostcore.db')
    c = conn.cursor()
    
    new_token = secrets.token_urlsafe(32)
    c.execute('UPDATE api_tokens SET token = ? WHERE user_id = ?',
             (new_token, session['user_id']))
    conn.commit()
    conn.close()
    
    flash('API token regenerated successfully!', 'success')
    return redirect(url_for('org_dashboard', org_name=session['org_name']))

if __name__ == '__main__':
    app.run(debug=True) 