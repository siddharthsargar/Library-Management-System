from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import datetime
import csv
from io import StringIO
from flask_restx import Api, Resource, fields

# Initialize the Flask application
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)  # Token expires in 1 hour

db = SQLAlchemy(app)
jwt = JWTManager(app)

api = Api(app, version='1.0', title='Library Management System API',
          description='A simple Library Management System API with JWT authentication')

# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'librarian' or 'user'

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    available_copies = db.Column(db.Integer, nullable=False)

class BorrowRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(20), default='pending')

class BorrowHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    return_date = db.Column(db.Date)

# Create database tables
with app.app_context():
    db.create_all()  # This creates the tables
    print("Tables created successfully!")
#db.create_all()

# Define API models using Swagger (Flask-RESTPlus)
borrow_request_model = api.model('BorrowRequest', {
    'book_id': fields.Integer(required=True, description='The book ID to borrow'),
    'start_date': fields.Date(required=True, description='Start date of the borrow'),
    'end_date': fields.Date(required=True, description='End date of the borrow'),
})

login_model = api.model('Login', {
    'email': fields.String(required=True, description='User email'),
    'password': fields.String(required=True, description='User password'),
})

# API to login and get JWT token
@api.route('/api/login')
class Login(Resource):
    @api.expect(login_model)
    def post(self):
        """Authenticate user and return JWT token"""
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return {'message': 'Missing email or password'}, 400
        
        user = User.query.filter_by(email=email).first()
        if not user or user.password != password:
            return {'message': 'Invalid credentials'}, 401
        
        # Create JWT token
        access_token = create_access_token(identity=email)
        return {'access_token': access_token}, 200

# API to export borrow history to CSV
@api.route('/api/export/history')
class ExportHistory(Resource):
    @jwt_required()
    def get(self):
        """Export borrow history of the logged-in user as CSV"""
        current_user_email = get_jwt_identity()
        user = User.query.filter_by(email=current_user_email).first()
        
        # Query borrow history for the authenticated user
        history = BorrowHistory.query.filter_by(user_id=user.id).all()
        
        if not history:
            return {'message': 'No borrow history found'}, 404
        
        # Prepare a CSV file
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header row
        writer.writerow(["Book ID", "Book Title", "Start Date", "End Date", "Return Date"])
        
        # Write data rows
        for borrow in history:
            book = Book.query.get(borrow.book_id)
            writer.writerow([book.id, book.title, borrow.start_date, borrow.end_date, borrow.return_date])
        
        # Move the cursor to the beginning of the StringIO buffer
        output.seek(0)
        
        # Send the CSV as a downloadable file
        return send_file(output, mimetype='text/csv', as_attachment=True, download_name='borrow_history.csv')

# API to get all books (authenticated users can view)
@api.route('/api/books')
class Books(Resource):
    @jwt_required()
    def get(self):
        """Get list of all books"""
        books = Book.query.all()
        books_data = [{"id": book.id, "title": book.title, "author": book.author, "available_copies": book.available_copies} for book in books]
        return books_data

# Start the Flask app
if __name__ == '__main__':
    app.run(debug=True)


