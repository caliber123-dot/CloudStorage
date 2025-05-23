from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_file, g
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
import os
import datetime
import secrets
from werkzeug.utils import secure_filename
from bson.objectid import ObjectId
import gridfs
from cryptography.fernet import Fernet
import base64
from dotenv import load_dotenv
from waitress import serve

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-secret-key')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'default-jwt-secret')
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['MONGO_URI'] = os.environ.get('MONGO_URI', 'mongokey')

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Connect to MongoDB
client = MongoClient(app.config['MONGO_URI'])
db = client.cloud_storage # cloud db name
fs = gridfs.GridFS(db)

# Security utilities
def generate_encryption_key():
    return Fernet.generate_key().decode('utf-8')

def encrypt_file(input_path, output_path, key=None):
    if key is None:
        key = generate_encryption_key()
    
    f = Fernet(key.encode('utf-8') if isinstance(key, str) else key)
    
    with open(input_path, 'rb') as in_file:
        data = in_file.read()
        encrypted_data = f.encrypt(data)
    
    with open(output_path, 'wb') as out_file:
        out_file.write(encrypted_data)
    
    return key

def decrypt_file(input_path, output_path, key):
    f = Fernet(key.encode('utf-8') if isinstance(key, str) else key)
    
    with open(input_path, 'rb') as in_file:
        encrypted_data = in_file.read()
        decrypted_data = f.decrypt(encrypted_data)
    
    with open(output_path, 'wb') as out_file:
        out_file.write(decrypted_data)
    
    return True

# User Authentication Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        
        # Check if user already exists
        existing_user = db.users.find_one({'email': email})
        if existing_user:
            flash('Email already registered', 'danger')
            return render_template('register.html')
        
        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # Generate verification token
        verification_token = secrets.token_urlsafe(32)
        
        # Create user
        new_user = {
            'email': email,
            'password': hashed_password,
            'name': name,
            'role': 'user',
            'created_at': datetime.datetime.utcnow(),
            'verified': False,
            'verification_token': verification_token,
            'settings': {
                'theme': 'light'
            }
        }
        
        db.users.insert_one(new_user)
        
        # In a real app, send verification email here
        flash('Account created! Please check your email to verify your account.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/verify/<token>')
def verify_email(token):
    user = db.users.find_one({'verification_token': token})
    
    if not user:
        flash('Invalid or expired verification token', 'danger')
        return redirect(url_for('login'))
    
    db.users.update_one(
        {'_id': user['_id']},
        {'$set': {'verified': True}, '$unset': {'verification_token': ''}}
    )
    
    flash('Email verified! You can now log in.', 'success')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Check if this is a Google login simulation
        if request.form.get('login_type') == 'google':
            # For demo purposes, create a simulated Google user
            google_email = request.form.get('google_email', 'demo@gmail.com')
            
            # Check if user exists, if not create one
            user = db.users.find_one({'email': google_email})
            if not user:
                new_user = {
                    'email': google_email,
                    'password': bcrypt.generate_password_hash('google-oauth-no-password').decode('utf-8'),
                    'name': google_email.split('@')[0],
                    'role': 'user',
                    'created_at': datetime.datetime.utcnow(),
                    'verified': True,  # Google users are pre-verified
                    'oauth_provider': 'google',
                    'settings': {
                        'theme': 'light'
                    }
                }
                user_id = db.users.insert_one(new_user).inserted_id
                user = db.users.find_one({'_id': user_id})
            
            # Create JWT token for Google user
            access_token = create_access_token(
                identity=str(user['_id']),
                expires_delta=datetime.timedelta(days=1)
            )
            
            # Update last login
            db.users.update_one(
                {'_id': user['_id']},
                {'$set': {'last_login': datetime.datetime.utcnow()}}
            )
            
            # Store in session
            session['user_id'] = str(user['_id'])
            session['email'] = user['email']
            session['name'] = user.get('name', 'User')
            session['role'] = user.get('role', 'user')
            session['jwt_token'] = access_token
            session['theme'] = user.get('settings', {}).get('theme', 'light')
            session['oauth_provider'] = 'google'
            
            flash(f'Logged in as {user["email"]} via Google', 'success')
            return redirect(url_for('dashboard'))
        
        # Regular email/password login
        user = db.users.find_one({'email': email})
        
        if not user or not bcrypt.check_password_hash(user['password'], password):
            flash('Invalid email or password', 'danger')
            return render_template('login.html')
        
        # DEMO MODE: Skip email verification check
        # if not user.get('verified', False):
        #     flash('Please verify your email before logging in', 'warning')
        #     return render_template('login.html')
        
        # Create JWT token
        access_token = create_access_token(
            identity=str(user['_id']),
            expires_delta=datetime.timedelta(days=1)
        )
        
        # Update last login
        db.users.update_one(
            {'_id': user['_id']},
            {'$set': {'last_login': datetime.datetime.utcnow()}}
        )
        
        # Store in session
        session['user_id'] = str(user['_id'])
        session['email'] = user['email']
        session['name'] = user.get('name', 'User')
        session['role'] = user.get('role', 'user')
        session['jwt_token'] = access_token
        session['theme'] = user.get('settings', {}).get('theme', 'light')
        
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash('Please log in to access your profile', 'warning')
        return redirect(url_for('login'))
    
    user = db.users.find_one({'_id': ObjectId(session['user_id'])})
    
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('logout'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        theme = request.form.get('theme')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Update basic info
        update_data = {
            'name': name,
            'settings.theme': theme
        }
        
        # Handle password change if provided
        if current_password and new_password and confirm_password:
            if not bcrypt.check_password_hash(user['password'], current_password):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('profile'))
            
            if new_password != confirm_password:
                flash('New passwords do not match', 'danger')
                return redirect(url_for('profile'))
            
            # Hash and update new password
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            update_data['password'] = hashed_password
            flash('Password updated successfully', 'success')
        
        # Update user in database
        db.users.update_one(
            {'_id': ObjectId(session['user_id'])},
            {'$set': update_data}
        )
        
        # Update session data
        session['name'] = name
        session['theme'] = theme
        
        flash('Profile updated successfully', 'success')
        return redirect(url_for('profile'))
    
    return render_template('profile.html', user=user)

# File Management Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get user's recent files
    recent_files = list(db.files.find({
        'owner_id': ObjectId(session['user_id']),
        'is_folder': False
    }).sort('updated_at', -1).limit(5))
    
    # Get storage usage
    storage_used = db.files.aggregate([
        {'$match': {'owner_id': ObjectId(session['user_id']), 'is_folder': False}},
        {'$group': {'_id': None, 'total': {'$sum': '$size'}}}
    ])
    
    storage_used = next(storage_used, {'total': 0})['total']
    storage_limit = 10 * 1024 * 1024 * 1024  # 10GB
    storage_percentage = min(100, (storage_used / storage_limit) * 100)
    
    return render_template(
        'dashboard.html',
        recent_files=recent_files,
        storage_used=storage_used,
        storage_limit=storage_limit,
        storage_percentage=storage_percentage
    )

@app.route('/files')
@app.route('/files/<folder>')
def files(folder=None):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get sort parameter
    sort_by = request.args.get('sort', 'date')
    
    # Query files and folders
    query = {
        'owner_id': ObjectId(session['user_id']),
        'parent_folder_id': ObjectId(folder) if folder else None,
        'deleted': {'$ne': True}
    }
    
    # Apply sorting
    sort_field = 'updated_at'
    sort_direction = -1
    
    if sort_by == 'name':
        sort_field = 'name'
        sort_direction = 1
    elif sort_by == 'size':
        sort_field = 'size'
        sort_direction = -1
    elif sort_by == 'type':
        sort_field = 'type'
        sort_direction = 1
    
    items = list(db.files.find(query).sort(sort_field, sort_direction))
    
    # Get current folder info
    current_folder = None
    breadcrumbs = []
    
    if folder:
        current_folder = db.files.find_one({
            '_id': ObjectId(folder),
            'owner_id': ObjectId(session['user_id']),
            'is_folder': True
        })
        
        if current_folder:
            # Build breadcrumbs
            parent_id = current_folder.get('parent_folder_id')
            while parent_id:
                parent = db.files.find_one({
                    '_id': parent_id,
                    'owner_id': ObjectId(session['user_id']),
                    'is_folder': True
                })
                if parent:
                    breadcrumbs.insert(0, {
                        'id': str(parent['_id']),
                        'name': parent['name']
                    })
                    parent_id = parent.get('parent_folder_id')
                else:
                    break
            
            breadcrumbs.append({
                'id': str(current_folder['_id']),
                'name': current_folder['name']
            })
    
    return render_template('files.html', 
                         items=items,
                         current_folder=current_folder,
                         breadcrumbs=breadcrumbs,
                         sort_by=sort_by)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        flash('Please log in to upload files', 'warning')
        return redirect(url_for('login'))
    
    if 'file' not in request.files:
        flash('No file selected', 'danger')
        return redirect(request.referrer or url_for('files'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(request.referrer or url_for('files'))
    
    folder_id = request.form.get('folder_id')
    
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{session['user_id']}_{datetime.datetime.utcnow().timestamp()}_{filename}")
        file.save(file_path)
        
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # Encrypt file
        encryption_key = encrypt_file(file_path, file_path)
        
        # Create file document
        file_doc = {
            'name': filename,
            'type': file.content_type,
            'size': file_size,
            'owner_id': ObjectId(session['user_id']),
            'parent_folder_id': ObjectId(folder_id) if folder_id else None,
            'is_folder': False,
            'created_at': datetime.datetime.utcnow(),
            'updated_at': datetime.datetime.utcnow(),
            'file_path': file_path,
            'encryption_key': encryption_key,
            'current_version': 1,
            'is_favorite': False,
            'tags': []
        }
        
        # Insert file
        file_id = db.files.insert_one(file_doc).inserted_id
        
        # Create initial version
        version = {
            'file_id': file_id,
            'version_number': 1,
            'created_at': datetime.datetime.utcnow(),
            'created_by': ObjectId(session['user_id']),
            'size': file_size,
            'file_path': file_path,
            'encryption_key': encryption_key
        }
        
        db.versions.insert_one(version)
        
        flash('File uploaded successfully', 'success')
        
        # Redirect back to the folder or files page
        if folder_id:
            return redirect(url_for('files', folder=folder_id))
        else:
            return redirect(url_for('files'))

    return jsonify({'error': 'File upload failed'}), 500

@app.route('/create-folder', methods=['POST'])
def create_folder():
    if 'user_id' not in session:
        flash('Please log in to create folders', 'warning')
        return redirect(url_for('login'))
    
    folder_name = request.form.get('folder_name')
    parent_folder_id = request.form.get('parent_folder_id')
    
    if not folder_name:
        flash('Folder name is required', 'danger')
        if parent_folder_id:
            return redirect(url_for('files', folder=parent_folder_id))
        else:
            return redirect(url_for('files'))
    
    folder = {
        'name': folder_name,
        'owner_id': ObjectId(session['user_id']),
        'parent_folder_id': ObjectId(parent_folder_id) if parent_folder_id else None,
        'is_folder': True,
        'created_at': datetime.datetime.utcnow(),
        'updated_at': datetime.datetime.utcnow(),
        'is_favorite': False,
        'tags': []
    }
    
    folder_id = db.files.insert_one(folder).inserted_id
    
    flash('Folder created successfully', 'success')
    
    if parent_folder_id:
        return redirect(url_for('files', folder=parent_folder_id))
    else:
        return redirect(url_for('files'))

# Trash routes
@app.route('/trash')
def trash():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get sort parameter
    sort_by = request.args.get('sort', 'date')
    
    # Query deleted items
    query = {
        'owner_id': ObjectId(session['user_id']),
        'deleted': True
    }
    
    # Apply sorting
    sort_field = 'deleted_at'
    sort_direction = -1
    
    if sort_by == 'name':
        sort_field = 'name'
        sort_direction = 1
    elif sort_by == 'size':
        sort_field = 'size'
        sort_direction = -1
    elif sort_by == 'type':
        sort_field = 'type'
        sort_direction = 1
    
    deleted_items = list(db.files.find(query).sort(sort_field, sort_direction))
    
    return render_template('trash.html', deleted_items=deleted_items)

@app.route('/restore/<item_id>', methods=['POST'])
def restore_item(item_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db.files.update_one(
        {'_id': ObjectId(item_id), 'owner_id': ObjectId(session['user_id'])},
        {'$set': {'deleted': False}, '$unset': {'deleted_at': ''}}
    )
    
    flash('Item restored successfully', 'success')
    return redirect(url_for('trash'))

@app.route('/permanently-delete/<item_id>', methods=['POST'])
def permanently_delete_item(item_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    item = db.files.find_one({'_id': ObjectId(item_id), 'owner_id': ObjectId(session['user_id'])})
    
    if item:
        # Delete file from storage if it's not a folder
        if not item.get('is_folder', False) and 'file_path' in item:
            try:
                os.remove(item['file_path'])
            except:
                pass
        
        # Delete from database
        db.files.delete_one({'_id': ObjectId(item_id)})
        
        # Delete versions if any
        db.versions.delete_many({'file_id': ObjectId(item_id)})
    
    flash('Item permanently deleted', 'success')
    return redirect(url_for('trash'))

@app.route('/empty-trash', methods=['POST'])
def empty_trash():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get all deleted files
    deleted_files = db.files.find({
        'owner_id': ObjectId(session['user_id']),
        'deleted': True,
        'is_folder': False
    })
    
    # Delete physical files
    for file in deleted_files:
        if 'file_path' in file:
            try:
                os.remove(file['file_path'])
            except:
                pass
    
    # Delete all items from database
    db.files.delete_many({
        'owner_id': ObjectId(session['user_id']),
        'deleted': True
    })
    
    # Delete associated versions
    db.versions.delete_many({
        'file_id': {'$in': [f['_id'] for f in deleted_files]}
    })
    
    flash('Trash emptied successfully', 'success')
    return redirect(url_for('trash'))
    
    
    # Favorites routes
@app.route('/favorites')
def favorites():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get sort parameter
    sort_by = request.args.get('sort', 'date')
    
    # Query favorite items
    query = {
        'owner_id': ObjectId(session['user_id']),
        'is_favorite': True,
        'deleted': {'$ne': True}
    }
    
    # Apply sorting
    sort_field = 'updated_at'
    sort_direction = -1
    
    if sort_by == 'name':
        sort_field = 'name'
        sort_direction = 1
    elif sort_by == 'size':
        sort_field = 'size'
        sort_direction = -1
    elif sort_by == 'type':
        sort_field = 'type'
        sort_direction = 1
    
    favorite_items = list(db.files.find(query).sort(sort_field, sort_direction))
    
    return render_template('favorites.html', favorite_items=favorite_items)

@app.route('/toggle-favorite/<item_id>', methods=['POST'])
def toggle_favorite(item_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Get current item
        item = db.files.find_one({
            '_id': ObjectId(item_id),
            'owner_id': ObjectId(session['user_id'])
        })
        
        if not item:
            return jsonify({'error': 'Item not found'}), 404
        
        # Toggle favorite status
        is_favorite = not item.get('is_favorite', False)
        
        # Update the item
        result = db.files.update_one(
            {'_id': ObjectId(item_id)},
            {'$set': {'is_favorite': is_favorite}}
        )
        
        if result.modified_count == 0:
            return jsonify({'error': 'Failed to update favorite status'}), 500
        
        return jsonify({
            'success': True,
            'is_favorite': is_favorite
        })
    except Exception as e:
        app.logger.error(f"Error toggling favorite: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/delete/<item_id>', methods=['POST'])
def delete_item(item_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Move to trash instead of deleting
        result = db.files.update_one(
            {'_id': ObjectId(item_id), 'owner_id': ObjectId(session['user_id'])},
            {'$set': {'deleted': True, 'deleted_at': datetime.datetime.utcnow()}}
        )
        
        if result.modified_count == 0:
            return jsonify({'error': 'Item not found or access denied'}), 404
        
        return jsonify({'success': True, 'message': 'Item moved to trash'})
    except Exception as e:
        app.logger.error(f"Error deleting item: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/rename/<item_id>', methods=['POST'])
def rename_item(item_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    new_name = request.form.get('new_name')
    
    if not new_name:
        flash('Name cannot be empty', 'danger')
        return redirect(request.referrer or url_for('files'))
    
    # Get the current item to check its parent folder
    item = db.files.find_one({
        '_id': ObjectId(item_id),
        'owner_id': ObjectId(session['user_id'])
    })
    
    if not item:
        flash('Item not found', 'danger')
        return redirect(url_for('files'))
    
    # Update the item name
    db.files.update_one(
        {'_id': ObjectId(item_id), 'owner_id': ObjectId(session['user_id'])},
        {'$set': {'name': new_name, 'updated_at': datetime.datetime.utcnow()}}
    )
    
    flash('Item renamed successfully', 'success')
    
    # Redirect back to the current folder
    if item.get('parent_folder_id'):
        return redirect(url_for('files', folder=str(item['parent_folder_id'])))
    else:
        return redirect(url_for('files'))

@app.route('/share/<item_id>', methods=['POST'])
def share_item(item_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    share_type = request.form.get('share_type')
    is_public = request.form.get('is_public') == 'true'
    permissions = request.form.get('permissions', 'view').split(',')
    
    # Get the item
    item = db.files.find_one({
        '_id': ObjectId(item_id),
        'owner_id': ObjectId(session['user_id'])
    })
    
    if not item:
        flash('Item not found', 'danger')
        return redirect(url_for('files'))
    
    if is_public or share_type == 'public':
        # Generate a public share link
        share_token = secrets.token_urlsafe(16)
        
        share = {
            'item_id': ObjectId(item_id),
            'owner_id': ObjectId(session['user_id']),
            'is_public': True,
            'token': share_token,
            'permissions': permissions,
            'created_at': datetime.datetime.utcnow()
        }
        
        db.shares.insert_one(share)
        
        flash(f'Public share link created: {request.host_url}s/{share_token}', 'success')
    else:
        # Share with specific user
        shared_with_email = request.form.get('shared_with')
        
        if not shared_with_email:
            flash('Email address is required for sharing with a user', 'danger')
            return redirect(request.referrer or url_for('files'))
        
        # Check if user exists
        shared_with_user = db.users.find_one({'email': shared_with_email})
        
        if not shared_with_user:
            flash(f'User with email {shared_with_email} not found', 'warning')
            return redirect(request.referrer or url_for('files'))
        
        # Create share
        share = {
            'item_id': ObjectId(item_id),
            'owner_id': ObjectId(session['user_id']),
            'shared_with_id': shared_with_user['_id'],
            'is_public': False,
            'permissions': permissions,
            'created_at': datetime.datetime.utcnow()
        }
        
        db.shares.insert_one(share)
        
        flash(f'Item shared with {shared_with_email}', 'success')
    
    # Redirect back to the referring page
    referrer = request.referrer
    if referrer and 'favorites' in referrer:
        return redirect(url_for('favorites'))
    elif referrer and 'files' in referrer:
        folder_id = request.args.get('folder')
        if folder_id:
            return redirect(url_for('files', folder=folder_id))
        else:
            return redirect(url_for('files'))
    else:
        return redirect(url_for('dashboard'))

@app.route('/preview/<file_id>')
def preview_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    file = db.files.find_one({
        '_id': ObjectId(file_id),
        'is_folder': False
    })
    
    if not file:
        flash('File not found', 'danger')
        return redirect(url_for('files'))
    
    # Check if user has access
    if str(file['owner_id']) != session['user_id']:
        # Check if file is shared with user
        share = db.shares.find_one({
            'item_id': ObjectId(file_id),
            '$or': [
                {'shared_with': ObjectId(session['user_id'])},
                {'is_public': True}
            ],
            'permissions': {'$regex': 'view'}
        })
        
        if not share:
            flash('Access denied', 'danger')
            return redirect(url_for('files'))
    
    # Create temporary decrypted file
    temp_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'temp')
    os.makedirs(temp_dir, exist_ok=True)
    
    decrypted_path = os.path.join(temp_dir, f"preview_{file['name']}")
    
    try:
        # Decrypt file
        decrypt_file(file['file_path'], decrypted_path, file['encryption_key'])
        
        # For images and PDFs, serve the decrypted file directly
        if 'image' in file.get('type', '') or 'pdf' in file.get('type', ''):
            return send_file(
                decrypted_path,
                mimetype=file['type']
            )
        # For text files, read and return the content
        elif 'text' in file.get('type', '') or 'json' in file.get('type', '') or 'xml' in file.get('type', '') or 'html' in file.get('type', ''):
            with open(decrypted_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return content
        else:
            return "Preview not available for this file type"
    except Exception as e:
        app.logger.error(f"Error previewing file: {str(e)}")
        return "Error previewing file", 500
    finally:
        # Clean up temporary file
        try:
            if os.path.exists(decrypted_path):
                os.remove(decrypted_path)
        except:
            pass

@app.route('/download/<file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    file = db.files.find_one({
        '_id': ObjectId(file_id),
        'is_folder': False
    })
    
    if not file:
        flash('File not found', 'danger')
        return redirect(url_for('files'))
    
    # Check if user has access
    if str(file['owner_id']) != session['user_id']:
        # Check if file is shared with user
        share = db.shares.find_one({
            'file_id': ObjectId(file_id),
            '$or': [
                {'shared_with': ObjectId(session['user_id'])},
                {'is_public': True}
            ],
            'permissions': {'$regex': 'download'}
        })
        
        if not share:
            flash('Access denied', 'danger')
            return redirect(url_for('files'))
    
    # Create temporary decrypted file
    temp_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'temp')
    os.makedirs(temp_dir, exist_ok=True)
    
    decrypted_path = os.path.join(temp_dir, file['name'])
    
    try:
        # Decrypt file
        decrypt_file(file['file_path'], decrypted_path, file['encryption_key'])
        
        # Send file
        return send_file(
            decrypted_path,
            as_attachment=True,
            download_name=file['name'],
            mimetype=file['type']
        )
    except Exception as e:
        app.logger.error(f"Error downloading file: {str(e)}")
        flash('Error downloading file', 'danger')
        return redirect(url_for('files'))

@app.route('/api/delete/<item_id>', methods=['POST'])
def api_delete_item(item_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    item = db.files.find_one({
        '_id': ObjectId(item_id),
        'owner_id': ObjectId(session['user_id'])
    })
    
    if not item:
        return jsonify({'error': 'Item not found or access denied'}), 404
    
    # Move to trash (soft delete)
    expiry_date = datetime.datetime.utcnow() + datetime.timedelta(days=30)
    
    # Create deleted document
    deleted = {
        'original_id': item['_id'],
        'owner_id': item['owner_id'],
        'deleted_at': datetime.datetime.utcnow(),
        'deleted_by': ObjectId(session['user_id']),
        'expiry_date': expiry_date,
        'data': item
    }
    
    db.deleted.insert_one(deleted)
    
    # Remove from files collection
    db.files.delete_one({'_id': ObjectId(item_id)})
    
    return jsonify({'success': True}), 200

@app.route('/api/trash')
def api_trash():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get deleted items
    deleted_items = list(db.deleted.find({
        'owner_id': ObjectId(session['user_id']),
        'expiry_date': {'$gt': datetime.datetime.utcnow()}
    }).sort('deleted_at', -1))
    
    return render_template('trash.html', items=deleted_items)

@app.route('/api/restore/<item_id>', methods=['POST'])
def api_restore_item(item_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    deleted_item = db.deleted.find_one({
        '_id': ObjectId(item_id),
        'owner_id': ObjectId(session['user_id']),
        'expiry_date': {'$gt': datetime.datetime.utcnow()}
    })
    
    if not deleted_item:
        return jsonify({'error': 'Item not found in trash or access denied'}), 404
    
    # Restore item
    original_data = deleted_item['data']
    original_data['_id'] = deleted_item['original_id']
    
    db.files.insert_one(original_data)
    
    # Remove from deleted collection
    db.deleted.delete_one({'_id': ObjectId(item_id)})
    
    return jsonify({'success': True}), 200

@app.route('/api/empty-trash', methods=['POST'])
def api_empty_trash():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Get all deleted items
    deleted_items = list(db.deleted.find({'owner_id': ObjectId(session['user_id'])}))
    
    # Delete actual files
    for item in deleted_items:
        if not item['data'].get('is_folder') and item['data'].get('file_path'):
            try:
                if os.path.exists(item['data']['file_path']):
                    os.remove(item['data']['file_path'])
            except Exception as e:
                app.logger.error(f"Error deleting file: {str(e)}")
    
    # Remove all from deleted collection
    result = db.deleted.delete_many({'owner_id': ObjectId(session['user_id'])})
    
    return jsonify({
        'success': True,
        'items_deleted': result.deleted_count
    }), 200

# Sharing Routes
@app.route('/shared')
def shared():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get items shared with user
    shared_with_me = list(db.shares.find({
        '$or': [
            {'shared_with': ObjectId(session['user_id'])},
            {'is_public': True, 'owner_id': {'$ne': ObjectId(session['user_id'])}}
        ]
    }))
    
    item_ids = [share['item_id'] for share in shared_with_me]
    shared_files = list(db.files.find({'_id': {'$in': item_ids}}))
    
    # Get items user has shared
    my_shares = list(db.shares.find({'owner_id': ObjectId(session['user_id'])}))
    my_shared_item_ids = [share['item_id'] for share in my_shares]
    my_shared_files = list(db.files.find({'_id': {'$in': my_shared_item_ids}}))
    
    return render_template(
        'shared.html',
        shared_with_me=shared_with_me,
        shared_files=shared_files,
        my_shares=my_shares,
        my_shared_files=my_shared_files
    )

@app.route('/share/<file_id>', methods=['POST'])
def share_file(file_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    file = db.files.find_one({
        '_id': ObjectId(file_id),
        'owner_id': ObjectId(session['user_id'])
    })
    
    if not file:
        return jsonify({'error': 'File not found or access denied'}), 404
    
    is_public = request.form.get('is_public') == 'true'
    permissions = request.form.get('permissions', 'view')
    shared_with_email = request.form.get('shared_with')
    
    # Generate share link token
    link_token = secrets.token_urlsafe(16)
    
    # Create share document
    share = {
        'file_id': ObjectId(file_id),
        'owner_id': ObjectId(session['user_id']),
        'is_public': is_public,
        'permissions': permissions,
        'link': f"/shared-file/{link_token}",
        'link_token': link_token,
        'created_at': datetime.datetime.utcnow(),
        'access_count': 0
    }
    
    # If not public, find user by email
    if not is_public and shared_with_email:
        shared_user = db.users.find_one({'email': shared_with_email})
        if shared_user:
            share['shared_with'] = shared_user['_id']
        else:
            return jsonify({'error': 'User not found'}), 404
    
    # Insert share
    share_id = db.shares.insert_one(share).inserted_id
    
    return jsonify({
        'success': True,
        'share_id': str(share_id),
        'link': f"/shared-file/{link_token}"
    }), 201

@app.route('/shared-file/<token>')
def access_shared_file(token):
    share = db.shares.find_one({'link_token': token})
    
    if not share:
        flash('Invalid or expired share link', 'danger')
        return redirect(url_for('index'))
    
    # Update access count
    db.shares.update_one(
        {'_id': share['_id']},
        {'$inc': {'access_count': 1}}
    )
    
    file = db.files.find_one({'_id': share['file_id']})
    
    if not file:
        flash('File not found', 'danger')
        return redirect(url_for('index'))
    
    # Check if user has access
    if not share.get('is_public'):
        if 'user_id' not in session:
            flash('Please log in to access this file', 'warning')
            return redirect(url_for('login'))
        
        if not share.get('shared_with') or str(share['shared_with']) != session['user_id']:
            flash('Access denied', 'danger')
            return redirect(url_for('index'))
    
    return render_template('shared_file.html', file=file, share=share)

# Search and Organization Routes
@app.route('/search')
def search():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    query = request.args.get('q', '')
    
    if not query:
        return jsonify({'results': []})
    
    # Build MongoDB query
    mongo_query = {
        'owner_id': ObjectId(session['user_id']),
        'deleted': {'$ne': True},
        '$or': [
            {'name': {'$regex': query, '$options': 'i'}},
            {'tags': {'$regex': query, '$options': 'i'}}
        ]
    }
    
    # Execute search
    results = list(db.files.find(mongo_query).sort('is_folder', -1).sort('name', 1).limit(10))
    
    # Convert ObjectId to string for JSON serialization
    for result in results:
        result['_id'] = str(result['_id'])
        result['owner_id'] = str(result['owner_id'])
        if 'parent_folder_id' in result:
            result['parent_folder_id'] = str(result['parent_folder_id'])
    
    return jsonify({'results': results})

@app.route('/api/favorites')
def api_favorites():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get favorite items
    favorites = list(db.files.find({
        'owner_id': ObjectId(session['user_id']),
        'is_favorite': True
    }).sort('is_folder', -1).sort('name', 1))
    
    return render_template('favorites.html', favorites=favorites)

@app.route('/api/toggle-favorite/<item_id>', methods=['POST'])
def api_toggle_favorite(item_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    item = db.files.find_one({
        '_id': ObjectId(item_id),
        'owner_id': ObjectId(session['user_id'])
    })
    
    if not item:
        return jsonify({'error': 'Item not found or access denied'}), 404
    
    # Toggle favorite status
    is_favorite = not item.get('is_favorite', False)
    
    db.files.update_one(
        {'_id': ObjectId(item_id)},
        {'$set': {'is_favorite': is_favorite}}
    )
    
    return jsonify({
        'success': True,
        'is_favorite': is_favorite
    }), 200

@app.route('/add-tag/<item_id>', methods=['POST'])
def add_tag(item_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    tag = request.form.get('tag')
    
    if not tag:
        return jsonify({'error': 'Tag is required'}), 400
    
    item = db.files.find_one({
        '_id': ObjectId(item_id),
        'owner_id': ObjectId(session['user_id'])
    })
    
    if not item:
        return jsonify({'error': 'Item not found or access denied'}), 404
    
    # Add tag if not already present
    if 'tags' not in item:
        item['tags'] = []
    
    if tag not in item['tags']:
        db.files.update_one(
            {'_id': ObjectId(item_id)},
            {'$push': {'tags': tag}}
        )
    
    return jsonify({'success': True}), 200

@app.route('/remove-tag/<item_id>/<tag>', methods=['POST'])
def remove_tag(item_id, tag):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    item = db.files.find_one({
        '_id': ObjectId(item_id),
        'owner_id': ObjectId(session['user_id'])
    })
    
    if not item:
        return jsonify({'error': 'Item not found or access denied'}), 404
    
    # Remove tag
    db.files.update_one(
        {'_id': ObjectId(item_id)},
        {'$pull': {'tags': tag}}
    )
    
    return jsonify({'success': True}), 200

# Version Management Routes
@app.route('/versions/<file_id>')
def file_versions(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    file = db.files.find_one({'_id': ObjectId(file_id)})
    
    if not file:
        flash('File not found', 'danger')
        return redirect(url_for('files'))
    
    # Check if user has access
    if str(file['owner_id']) != session['user_id']:
        # Check if file is shared with user
        share = db.shares.find_one({
            'file_id': ObjectId(file_id),
            '$or': [
                {'shared_with': ObjectId(session['user_id'])},
                {'is_public': True}
            ]
        })
        
        if not share:
            flash('Access denied', 'danger')
            return redirect(url_for('files'))
    
    # Get versions
    versions = list(db.versions.find({
        'file_id': ObjectId(file_id)
    }).sort('version_number', -1))
    
    return render_template('versions.html', file=file, versions=versions)

@app.route('/restore-version/<file_id>/<int:version_number>', methods=['POST'])
def restore_version(file_id, version_number):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    file = db.files.find_one({
        '_id': ObjectId(file_id),
        'owner_id': ObjectId(session['user_id'])
    })
    
    if not file:
        return jsonify({'error': 'File not found or access denied'}), 404
    
    # Check if version exists
    version = db.versions.find_one({
        'file_id': ObjectId(file_id),
        'version_number': version_number
    })
    
    if not version:
        return jsonify({'error': 'Version not found'}), 404
    
    # Create a new version based on the old one
    current_version = file.get('current_version', 1)
    new_version_number = current_version + 1
    
    # Copy the old version file
    source_path = version['file_path']
    new_path = os.path.join(app.config['UPLOAD_FOLDER'], 
                           f"{file_id}_v{new_version_number}_{datetime.datetime.utcnow().timestamp()}")
    
    import shutil
    shutil.copy2(source_path, new_path)
    
    # Create new version document
    new_version = {
        'file_id': ObjectId(file_id),
        'version_number': new_version_number,
        'created_at': datetime.datetime.utcnow(),
        'created_by': ObjectId(session['user_id']),
        'size': version['size'],
        'file_path': new_path,
        'encryption_key': version['encryption_key'],
        'restored_from': version_number
    }
    
    # Insert new version
    db.versions.insert_one(new_version)
    
    # Update file document with new version
    db.files.update_one(
        {'_id': ObjectId(file_id)},
        {
            '$set': {
                'current_version': new_version_number,
                'file_path': new_path,
                'encryption_key': version['encryption_key'],
                'size': version['size'],
                'updated_at': datetime.datetime.utcnow()
            }
        }
    )
    
    return jsonify({
        'success': True,
        'version': new_version_number
    }), 200

# Theme switching
@app.route('/toggle-theme', methods=['POST'])
def toggle_theme():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.get_json()
        new_theme = data.get('theme', 'light')
        
        if new_theme not in ['light', 'dark']:
            return jsonify({'error': 'Invalid theme'}), 400
        
        # Update session
        session['theme'] = new_theme
        
        # Update user settings in database
        db.users.update_one(
            {'_id': ObjectId(session['user_id'])},
            {'$set': {'settings.theme': new_theme}}
        )
        
        return jsonify({
            'success': True,
            'theme': new_theme
        })
    except Exception as e:
        app.logger.error(f"Error updating theme: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

# Template filters
@app.template_filter('format_size')
def format_size(size):
    # Convert bytes to human-readable format
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"

@app.template_filter('format_date')
def format_date(date):
    if not date:
        return ''
    return date.strftime('%b %d, %Y %H:%M')

# Context processors
@app.context_processor
def inject_user():
    storage_used = 0
    storage_limit = 10 * 1024 * 1024 * 1024  # 10 GB in bytes
    storage_percentage = 0
    
    if 'user_id' in session:
        # Calculate storage used
        storage_used_result = db.files.aggregate([
            {'$match': {'owner_id': ObjectId(session['user_id']), 'deleted': {'$ne': True}}},
            {'$group': {'_id': None, 'total': {'$sum': '$size'}}}
        ])
        storage_used = next(storage_used_result, {'total': 0})['total']
        storage_percentage = (storage_used / storage_limit * 100) if storage_limit > 0 else 0
    
    return {
        'user': {
            'id': session.get('user_id'),
            'email': session.get('email'),
            'name': session.get('name'),
            'role': session.get('role')
        } if 'user_id' in session else None,
        'theme': session.get('theme', 'light'),
        'storage_used': storage_used,
        'storage_limit': storage_limit,
        'storage_percentage': storage_percentage
    }

@app.before_request
def before_request():
    if 'user_id' in session:
        user = db.users.find_one({'_id': ObjectId(session['user_id'])})
        if user:
            g.user = user
            # Calculate storage used
            storage_used = db.files.aggregate([
                {'$match': {'owner_id': ObjectId(session['user_id']), 'deleted': {'$ne': True}}},
                {'$group': {'_id': None, 'total': {'$sum': '$size'}}}
            ])
            storage_used = next(storage_used, {'total': 0})['total']
            g.storage_used = storage_used
            g.storage_limit = 10 * 1024 * 1024 * 1024  # 10 GB in bytes
            g.storage_percentage = (storage_used / g.storage_limit * 100) if g.storage_limit > 0 else 0
    else:
        g.user = None
        g.storage_used = 0
        g.storage_limit = 10 * 1024 * 1024 * 1024
        g.storage_percentage = 0

if __name__ == '__main__':
    # app.run(host='0.0.0.0', debug=True)
    serve(app, host="0.0.0.0", port=5000)
