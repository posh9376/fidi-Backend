import os
from datetime import datetime
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from dotenv import load_dotenv
from marshmallow import Schema, fields
from sqlalchemy import func

load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*", "allow_headers": "*", "expose_headers": "*"}})
DB_CONFIG = {
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASS' ),
    'host': os.getenv('DB_HOST'),
    'port': os.getenv('DB_PORT'),
    'database': os.getenv('DB_NAME'),
}

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{DB_CONFIG["user"]}:{DB_CONFIG["password"]}@{DB_CONFIG["host"]}:{DB_CONFIG["port"]}/{DB_CONFIG["database"]}'
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your_secret_key')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(256), nullable=False)

    # Define relationships
    todos = db.relationship('TODO', back_populates='user', lazy=True)
    notes = db.relationship('Notes', back_populates='user', lazy=True)

class UserSchema(Schema):
    id = fields.Int()
    name = fields.Str()
    email = fields.Email()

class TODO(db.Model):
    __tablename__ = 'todos'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    done_by = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # Define relationships
    user = db.relationship('User', back_populates='todos', lazy=True)

class TodoSchema(Schema):
    id = fields.Int()
    title = fields.Str()
    description = fields.Str()
    done_by = fields.DateTime()
    created_at = fields.DateTime()
    user_id = fields.Int()
    remaining_time = fields.Method("get_remaining_time")

    def get_remaining_time(self, obj):
        if obj.done_by and obj.created_at:
            return (obj.done_by - obj.created_at).total_seconds()
        return None

class Notes(db.Model):
    __tablename__ = 'notes'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # Define relationships
    user = db.relationship('User', back_populates='notes', lazy=True)

class NotesSchema(Schema):
    id = fields.Int()
    text = fields.Str()
    user_id = fields.Int()

@app.route('/', methods=['GET'])
def index():
    return 'Welcome to the TODO API'

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'message': 'Email and Password are required'}), 400
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'User not found.Please signup'}), 401
    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid password'}), 401
    # Generate and return JWT
    access_token = create_access_token(identity=user.id)
    return jsonify({'message': 'Login successful', 'access_token': access_token, 'user': UserSchema().dump(user)}), 200

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    if not name or not email or not password:
        return jsonify({'message': 'Name, Email, and Password are required'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'User already exists. Please login'}), 400
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(name=name, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/todoos', methods=['GET'])
@jwt_required()
def get_todos():
    if not get_jwt_identity():
        return jsonify({'message': 'Unauthorized. No Token presesnt'}), 401
    user_id = get_jwt_identity()
    print(f'User ID: {user_id}')
    todos = TODO.query.filter_by(user_id=user_id).all()
    return jsonify(TodoSchema(many=True).dump(todos)), 200

@app.route('/todos', methods=['POST'])
@jwt_required()
def create_todo():
    user_id = get_jwt_identity()
    data = request.get_json()
    title = data.get('title')
    description = data.get('description')
    done_by = data.get('done_by')
    if not title or not description or not done_by:
        return jsonify({'message': 'Title, Description, and Done By are required'}), 400
    try:
        done_by = datetime.strptime(done_by, '%Y-%m-%d %H:%M:%S')
        if done_by < datetime.now():
            return jsonify({'message': 'Done by cannot be in the past'}), 400
    except ValueError:
        return jsonify({'message': 'Invalid date format. Use YYYY-MM-DD HH:MM:SS'}), 400
    todo = TODO(title=title, description=description, done_by=done_by, user_id=user_id)
    db.session.add(todo)
    db.session.commit()
    return jsonify({'message': 'Todo created successfully'}), 201

@app.route('/notes', methods=['GET'])
@jwt_required()
def get_notes():
    if not get_jwt_identity():
        return jsonify({'message': 'Unauthorized. No Token presesnt'}), 401
    user_id = get_jwt_identity()
    print(f'User ID: {user_id}')
    notes = Notes.query.filter_by(user_id=user_id).all()
    return jsonify(NotesSchema(many=True).dump(notes)), 200

@app.route('/notes', methods=['POST'])
@jwt_required()
def create_note():
    if not get_jwt_identity():
        return jsonify({'message': 'Unauthorized. No Token present'}), 401
    user_id = get_jwt_identity()
    data = request.get_json()
    text = data.get('text')
    if not text:
        return jsonify({'message': 'Text is required!'}), 400
    note = Notes(text=text, user_id=user_id)
    db.session.add(note)
    db.session.commit()
    return jsonify({'message': 'Note created successfully'}), 201

@app.route('/notes/<int:note_id>', methods=['DELETE'])
@jwt_required()
def delete_note(note_id):
    if not get_jwt_identity():
        return jsonify({'message': 'Unauthorized. No Token presesnt'}), 401
    user_id = get_jwt_identity()
    note = Notes.query.filter_by(id=note_id, user_id=user_id).first()
    if not note:
        return jsonify({'message': 'Note not found'}), 404
    db.session.delete(note)
    db.session.commit()
    return jsonify({'message': 'Note deleted successfully'}), 200
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))  # Get port from environment, default to 5000
    app.run(debug=False, host='0.0.0.0', port=port)
