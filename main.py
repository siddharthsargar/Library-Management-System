from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import datetime
import csv
from io import StringIO, BytesIO
from flask_restx import Api, Resource, fields, reqparse
from datetime import datetime, timedelta
#from flask_restplus import Resource, reqparse

# Initialize the Flask application
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'
# Configure the JWT expiration time
#app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)  # Token expires in 1 hour
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Token expires in 1 hour

db = SQLAlchemy(app)
jwt = JWTManager(app)

api = Api(app, version='1.0', title='Library Management System API',
          description='A simple Library Management System API with JWT authentication')

# Database models
# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     email = db.Column(db.String(100), unique=True, nullable=False)
#     password = db.Column(db.String(100), nullable=False)
#     role = db.Column(db.String(10), nullable=False)  # 'librarian' or 'user'

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'librarian' or 'user'
    borrow_requests = db.relationship('BorrowRequest', backref='user', lazy=True)
    borrow_history = db.relationship('BorrowHistory', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.email}>'


# class Book(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     title = db.Column(db.String(100), nullable=False)
#     author = db.Column(db.String(100), nullable=False)
#     available_copies = db.Column(db.Integer, nullable=False)

class Book(db.Model):
    __tablename__ = 'books'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(255), nullable=False)
    author = db.Column(db.String(255), nullable=False)
    available_copies = db.Column(db.Integer, nullable=False, default=0)
    borrow_requests = db.relationship('BorrowRequest', backref='book', lazy=True)

    def __repr__(self):
        return f'<Book {self.title} by {self.author}>'


# class BorrowRequest(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
#     start_date = db.Column(db.Date, nullable=False)
#     end_date = db.Column(db.Date, nullable=False)
#     status = db.Column(db.String(20), default='pending')

class BorrowRequest(db.Model):
    __tablename__ = 'borrow_requests'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(50), nullable=False, default='pending')  # 'pending', 'approved', 'denied'
    return_date = db.Column(db.Date, nullable=True)

    def __repr__(self):
        return f'<BorrowRequest {self.book_id} for User {self.user_id}>'


# class BorrowHistory(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
#     start_date = db.Column(db.Date, nullable=False)
#     end_date = db.Column(db.Date, nullable=False)
#     return_date = db.Column(db.Date)

class BorrowHistory(db.Model):
    __tablename__ = 'borrow_history'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    return_date = db.Column(db.Date, nullable=True)

    def __repr__(self):
        return f'<BorrowHistory {self.book_id} for User {self.user_id}>'

# Create database tables
with app.app_context():
    db.create_all()  # This creates the tables
    print("Tables created successfully!")
#db.create_all()

# # Define API models using Swagger (Flask-RESTPlus)
# borrow_request_model = api.model('BorrowRequest', {
#     'book_id': fields.Integer(required=True, description='The book ID to borrow'),
#     'start_date': fields.Date(required=True, description='Start date of the borrow'),
#     'end_date': fields.Date(required=True, description='End date of the borrow'),
# })

# login_model = api.model('Login', {
#     'email': fields.String(required=True, description='User email'),
#     'password': fields.String(required=True, description='User password'),
# })

# book_model = api.model('Book', {
#     'title': fields.String(required=True, description='The title of the book'),
#     'author': fields.String(required=True, description='The author of the book'),
#     'available_copies': fields.Integer(required=True, description='Number of available copies')
# })

# # API to login and get JWT token
# @api.route('/api/login')
# class Login(Resource):
#     @api.expect(login_model)
#     def post(self):
#         """Authenticate user and return JWT token"""
#         data = request.get_json()
#         #print("data is",data)
#         email = data.get('email')
#         #print("email is",email)
#         password = data.get('password')
#         #print("password is",password)
        
#         if not email or not password:
#             return {'message': 'Missing email or password'}, 400
        
#         user = User.query.filter_by(email=email).first()
#         print("user is",user)
#         if not user or user.password != password:
#             return {'message': 'Invalid credentials'}, 401
        
#         # Create JWT token
#         access_token = create_access_token(identity=email)
#         return {'access_token': access_token}, 200
    
# @api.route('/api/users')
# class Users(Resource):
#     def post(self):
#         """Create a new user"""
#         data = request.get_json()
#         email = data.get('email')
#         password = data.get('password')
#         role = data.get('role')  # 'librarian' or 'user'

#         if not email or not password or not role:
#             return {'message': 'Missing required fields'}, 400
        
#         if role not in ['librarian', 'user']:
#             return {'message': 'Invalid role, must be "librarian" or "user"'}, 400

#         # Check if the email already exists
#         if User.query.filter_by(email=email).first():
#             return {'message': 'User with this email already exists'}, 409
        
#         # Create and add the user
#         new_user = User(email=email, password=password, role=role)
#         db.session.add(new_user)
#         db.session.commit()

#         return {'message': 'User created successfully'}, 201
    
# @api.route('/api/book')
# class AddBook(Resource):
#     @api.expect(book_model)
#     @jwt_required()  # Ensure the user is authenticated
#     def post(self):
#         """
#         Add a new book to the library
#         """
#         current_user_email = get_jwt_identity()
#         user = User.query.filter_by(email=current_user_email).first()

#         # Check if the user has librarian privileges
#         if user.role != 'librarian':
#             return {'message': 'Only librarians can add books'}, 403

#         # Parse the input data
#         data = request.get_json()
#         title = data.get('title')
#         author = data.get('author')
#         available_copies = data.get('available_copies')

#         # Validate the input data
#         if not title or not author or available_copies is None or available_copies < 0:
#             return {'message': 'Invalid input data'}, 400

#         # Add the book to the database
#         new_book = Book(title=title, author=author, available_copies=available_copies)
#         db.session.add(new_book)
#         db.session.commit()

#         return {'message': 'Book added successfully', 'book_id': new_book.id}, 201


# # API to export borrow history to CSV
# @api.route('/api/export/history')
# class ExportHistory(Resource):
#     @jwt_required()
#     def get(self):
#         """Export borrow history of the logged-in user as CSV"""
#         current_user_email = get_jwt_identity()
#         user = User.query.filter_by(email=current_user_email).first()
        
#         # Query borrow history for the authenticated user
#         history = BorrowHistory.query.filter_by(user_id=user.id).all()
        
#         if not history:
#             return {'message': 'No borrow history found'}, 404
        
#         # Prepare a CSV file
#         output = StringIO()
#         writer = csv.writer(output)
        
#         # Write header row
#         writer.writerow(["Book ID", "Book Title", "Start Date", "End Date", "Return Date"])
        
#         # Write data rows
#         for borrow in history:
#             book = Book.query.get(borrow.book_id)
#             writer.writerow([book.id, book.title, borrow.start_date, borrow.end_date, borrow.return_date])
        
#         # Move the cursor to the beginning of the StringIO buffer
#         output.seek(0)
        
#         # Send the CSV as a downloadable file
#         return send_file(output, mimetype='text/csv', as_attachment=True, download_name='borrow_history.csv')

# # API to get all books (authenticated users can view)
# @api.route('/api/books')
# class Books(Resource):
#     @jwt_required()
#     def get(self):
#         """Get list of all books"""
#         books = Book.query.all()
#         books_data = [{"id": book.id, "title": book.title, "author": book.author, "available_copies": book.available_copies} for book in books]
#         return books_data
    


#--------------------------New Apis--------------------------

# Define API models using Swagger (Flask-RESTPlus)
user_model = api.model('User', {
    'email': fields.String(required=True, description='User email address'),
    'password': fields.String(required=True, description='User password'),
    'role': fields.String(required=True, description='User role, either "librarian" or "user"')
})


login_model = api.model('Login', {
    'email': fields.String(required=True, description='User email address'),
    'password': fields.String(required=True, description='User password')
})


book_model = api.model('Book', {
    'id': fields.Integer(required=True, description='The unique identifier of a book'),
    'title': fields.String(required=True, description='The title of the book'),
    'author': fields.String(required=True, description='The author of the book'),
    'available_copies': fields.Integer(required=True, description='Number of available copies of the book')
})


borrow_request_model = api.model('BorrowRequest', {
    'book_id': fields.Integer(required=True, description='The book ID to borrow'),
    'start_date': fields.Date(required=True, description='Start date of the borrow'),
    'end_date': fields.Date(required=True, description='End date of the borrow')
})


borrow_history_model = api.model('BorrowHistory', {
    'book_id': fields.Integer(required=True, description='The book ID'),
    'start_date': fields.Date(required=True, description='Start date of the borrow'),
    'end_date': fields.Date(required=True, description='End date of the borrow'),
    'return_date': fields.Date(required=False, description='Date when the book was returned')
})


borrow_request_action_model = api.model('BorrowRequestAction', {
    'action': fields.String(required=True, description='Action to be taken on the borrow request', enum=['approve', 'deny'])
})


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
        
        user_all = User.query.filter_by(email=email)
        print("user_all is",user_all)
        user = User.query.filter_by(email=email).first()
        print("user is",user)
        if not user or user.password != password:
            return {'message': 'Invalid credentials'}, 401
        
        access_token = create_access_token(identity=email)
        return {'access_token': access_token}, 200


# API to create a new library user (for librarians)
@api.route('/api/users/create')
class CreateUser(Resource):
    @jwt_required()  # Only librarians can create new users
    def post(self):
        """Create a new user (librarian only)"""
        current_user_email = get_jwt_identity()
        user = User.query.filter_by(email=current_user_email).first()

        # Check if the user has librarian privileges
        if user.role != 'librarian':
            return {'message': 'Only librarians can create users'}, 403

        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')  # 'librarian' or 'user'

        if not email or not password or not role:
            return {'message': 'Missing required fields'}, 400
        
        if role not in ['librarian', 'user']:
            return {'message': 'Invalid role, must be "librarian" or "user"'}, 400

        # Check if the email already exists
        if User.query.filter_by(email=email).first():
            return {'message': 'User with this email already exists'}, 409

        # Create and add the user
        new_user = User(email=email, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()

        return {'message': 'User created successfully'}, 201
    

#Add Book API (Librarian only)
@api.route('/api/book')
class AddBook(Resource):
    @jwt_required()  # Ensure the user is authenticated
    @api.expect(book_model)
    def post(self):
        """Add a new book to the library"""
        current_user_email = get_jwt_identity()
        user = User.query.filter_by(email=current_user_email).first()

        if user.role != 'librarian':
            return {'message': 'Only librarians can add books'}, 403

        data = request.get_json()
        title = data.get('title')
        author = data.get('author')
        available_copies = data.get('available_copies')

        if not title or not author or available_copies is None or available_copies < 0:
            return {'message': 'Invalid input data'}, 400

        new_book = Book(title=title, author=author, available_copies=available_copies)
        db.session.add(new_book)
        db.session.commit()

        return {'message': 'Book added successfully', 'book_id': new_book.id}, 201


#Submit Borrow Request API (Library User)
# @api.route('/api/borrow')
# class BorrowBook(Resource):
#     @jwt_required()
#     @api.expect(borrow_request_model)
#     def post(self):
#         """Submit a request to borrow a book"""
#         current_user_email = get_jwt_identity()
#         user = User.query.filter_by(email=current_user_email).first()

#         data = request.get_json()
#         book_id = data.get('book_id')
#         start_date = data.get('start_date')
#         end_date = data.get('end_date')

#         if not book_id or not start_date or not end_date:
#             return {'message': 'Missing required fields'}, 400
        
#         book = Book.query.get(book_id)
#         if not book:
#             return {'message': 'Book not found'}, 404

#         borrow_request = BorrowRequest(book_id=book_id, user_id=user.id, start_date=start_date, end_date=end_date)
#         db.session.add(borrow_request)
#         db.session.commit()

#         return {'message': 'Borrow request submitted successfully'}, 201

@api.route('/api/borrow')
# class BorrowBook(Resource):
#     @jwt_required()  # Ensure the user is authenticated
#     @api.expect(borrow_request_model)
#     def post(self):
#         """Submit a request to borrow a book"""
#         current_user_email = get_jwt_identity()
#         user = User.query.filter_by(email=current_user_email).first()

#         # Get data from the request
#         data = request.get_json()
#         book_id = data.get('book_id')
#         start_date = data.get('start_date')
#         end_date = data.get('end_date')

#         # Validate the input data
#         if not book_id or not start_date or not end_date:
#             return {'message': 'Missing required fields'}, 400

#         # Validate the date format
#         try:
#             start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
#             end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
#         except ValueError:
#             return {'message': 'Invalid date format. Please use YYYY-MM-DD'}, 400

#         # Check if the book exists
#         book = Book.query.get(book_id)
#         if not book:
#             return {'message': 'Book not found'}, 404

#         # Check for overlapping borrow dates for the same book
#         overlapping_borrows = BorrowRequest.query.filter(
#             BorrowRequest.book_id == book_id,
#             BorrowRequest.status == 'approved',
#             (BorrowRequest.start_date <= end_date) & (BorrowRequest.end_date >= start_date)
#         ).all()
#         print("overlapping_borrows is",overlapping_borrows)

#         # If there are overlapping borrow requests, return an error
#         if overlapping_borrows:
#             return {'message': 'The book is already borrowed during the requested period'}, 400

#         # If no overlap, create the borrow request
#         borrow_request = BorrowRequest(book_id=book_id, user_id=user.id, start_date=start_date, end_date=end_date, status='pending')
#         db.session.add(borrow_request)
#         db.session.commit()

#         return {'message': 'Borrow request submitted successfully'}, 201
class BorrowBook(Resource):
    @jwt_required()  # Ensure the user is authenticated
    @api.expect(borrow_request_model)
    def post(self):
        """Submit a request to borrow a book"""
        current_user_email = get_jwt_identity()
        user = User.query.filter_by(email=current_user_email).first()

        # Get data from the request
        data = request.get_json()
        book_id = data.get('book_id')
        start_date = data.get('start_date')
        end_date = data.get('end_date')

        # Validate the input data
        if not book_id or not start_date or not end_date:
            return {'message': 'Missing required fields'}, 400

        # Validate the date format
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        except ValueError:
            return {'message': 'Invalid date format. Please use YYYY-MM-DD'}, 400

        # Check if the book exists
        book = Book.query.get(book_id)
        if not book:
            return {'message': 'Book not found'}, 404

        # Check for overlapping borrow dates for the same book
        overlapping_borrows = BorrowRequest.query.filter(
            BorrowRequest.book_id == book_id,
            BorrowRequest.user_id == user.id,  # Make sure it’s the same user
            BorrowRequest.status == 'pending',  # Only check pending requests
            (BorrowRequest.start_date <= end_date) & (BorrowRequest.end_date >= start_date)
        ).all()
        print("overlapping_borrows is", overlapping_borrows)

        # If there are overlapping borrow requests, return an error
        if overlapping_borrows:
            return {'message': 'You have already submitted a borrow request for this book during the same period.'}, 400

        # If no overlap, create the borrow request
        borrow_request = BorrowRequest(book_id=book_id, user_id=user.id, start_date=start_date, end_date=end_date, status='pending')
        db.session.add(borrow_request)
        db.session.commit()

        return {'message': 'Borrow request submitted successfully'}, 201



# API to view all book borrow requests (only for librarians)
@api.route('/api/borrow-requests')
# class BorrowRequests(Resource):
#     @jwt_required()
#     def get(self):
#         """View all book borrow requests (librarians only)"""
#         current_user_email = get_jwt_identity()
#         user = User.query.filter_by(email=current_user_email).first()

#         # Check if the user has librarian privileges
#         if user.role != 'librarian':
#             return {'message': 'Only librarians can view borrow requests'}, 403
        
#         # Get all borrow requests
#         borrow_requests = BorrowRequest.query.all()
#         requests_data = [
#             {
#                 'id': req.id,
#                 'book_id': req.book_id,
#                 'user_id': req.user_id,
#                 'start_date': req.start_date,
#                 'end_date': req.end_date,
#                 'status': req.status
#             }
#             for req in borrow_requests
#         ]
#         return requests_data
class BorrowRequests(Resource):
    @jwt_required()
    def get(self):
        """View all book borrow requests (librarians only)"""
        current_user_email = get_jwt_identity()
        user = User.query.filter_by(email=current_user_email).first()

        # Check if the user has librarian privileges
        if user.role != 'librarian':
            return {'message': 'Only librarians can view borrow requests'}, 403
        
        # Get all borrow requests
        borrow_requests = BorrowRequest.query.all()
        requests_data = [
            {
                'id': req.id,
                'book_id': req.book_id,
                'user_id': req.user_id,
                'start_date': req.start_date.strftime('%Y-%m-%d') if req.start_date else None,
                'end_date': req.end_date.strftime('%Y-%m-%d') if req.end_date else None,
                'status': req.status
            }
            for req in borrow_requests
        ]
        
        return requests_data


# API to approve or deny a borrow request (only for librarians)
@api.route('/api/borrow-request/<int:request_id>/approve')
class ApproveBorrowRequest(Resource):
    @jwt_required()
    def put(self, request_id):
        """Approve or deny a borrow request (librarians only)"""
        current_user_email = get_jwt_identity()
        user = User.query.filter_by(email=current_user_email).first()

        # Check if the user has librarian privileges
        if user.role != 'librarian':
            return {'message': 'Only librarians can approve or deny borrow requests'}, 403
        
        # Get the borrow request by ID
        borrow_request = BorrowRequest.query.get(request_id)
        if not borrow_request:
            return {'message': 'Borrow request not found'}, 404
        
        data = request.get_json()
        action = data.get('action')  # 'approve' or 'deny'
        
        if action not in ['approve', 'deny']:
            return {'message': 'Invalid action, must be "approve" or "deny"'}, 400
        
        if action == 'approve':
            # Approve the borrow request and update the book's available copies
            book = Book.query.get(borrow_request.book_id)
            if book and book.available_copies > 0:
                book.available_copies -= 1
                borrow_request.status = 'approved'
                db.session.commit()
                return {'message': 'Borrow request approved'}, 200
            else:
                return {'message': 'Not enough available copies to approve request'}, 400
        else:
            # Deny the borrow request
            borrow_request.status = 'denied'
            db.session.commit()
            return {'message': 'Borrow request denied'}, 200


# API to view a user's book borrow history (only for librarians)
# @api.route('/api/user-history/<int:user_id>')
# class UserBorrowHistory(Resource):
#     @jwt_required()
#     def get(self, user_id):
#         """View a user's book borrow history (librarians only)"""
#         current_user_email = get_jwt_identity()
#         user = User.query.filter_by(email=current_user_email).first()

#         # Check if the user has librarian privileges
#         if user.role != 'librarian':
#             return {'message': 'Only librarians can view user borrow history'}, 403
        
#         # Get borrow history for the specified user
#         borrow_history = BorrowHistory.query.filter_by(user_id=user_id).all()
#         if not borrow_history:
#             return {'message': 'No borrow history found for this user'}, 404
        
#         history_data = [
#             {
#                 'book_id': history.book_id,
#                 'start_date': history.start_date,
#                 'end_date': history.end_date,
#                 'return_date': history.return_date
#             }
#             for history in borrow_history
#         ]
#         return history_data


# Library User APIs:
# API to get a list of all books (for users)
@api.route('/api/books')
class Books(Resource):
    @jwt_required()
    def get(self):
        """Get list of all books"""
        books = Book.query.all()
        books_data = [{"id": book.id, "title": book.title, "author": book.author, "available_copies": book.available_copies} for book in books]
        return books_data

# API to submit a request to borrow a book
# @api.route('/api/borrow')
# class BorrowBook(Resource):
#     @jwt_required()
#     @api.expect(borrow_request_model)
#     def post(self):
#         """Submit a request to borrow a book"""
#         current_user_email = get_jwt_identity()
#         user = User.query.filter_by(email=current_user_email).first()

#         # Parse input data
#         data = request.get_json()
#         book_id = data.get('book_id')
#         start_date = data.get('start_date')
#         end_date = data.get('end_date')

#         # Validate the input
#         if not book_id or not start_date or not end_date:
#             return {'message': 'Missing required fields'}, 400
        
#         # Check if the book exists
#         book = Book.query.get(book_id)
#         if not book:
#             return {'message': 'Book not found'}, 404
        
#         # Create borrow request
#         borrow_request = BorrowRequest(book_id=book_id, user_id=user.id, start_date=start_date, end_date=end_date)
#         db.session.add(borrow_request)
#         db.session.commit()

#         return {'message': 'Borrow request submitted successfully'}, 201

#Insert a new borrow history record
@api.route('/api/borrow-history')
class InsertBorrowHistory(Resource):
    @jwt_required()  # Ensure the user is authenticated
    @api.expect(borrow_history_model)  # Validate the input data structure
    def post(self):
        """Insert a new borrow history record"""
        current_user_email = get_jwt_identity()
        user = User.query.filter_by(email=current_user_email).first()

        # Parse input data
        data = request.get_json()
        book_id = data.get('book_id')
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        return_date = data.get('return_date', None)  # Return date is optional

        # Validate the input data
        if not book_id or not start_date or not end_date:
            return {'message': 'Missing required fields'}, 400

        # Validate the date format
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
            if return_date:
                return_date = datetime.strptime(return_date, '%Y-%m-%d').date()  # If return_date is provided, validate it as well
        except ValueError:
            return {'message': 'Invalid date format. Please use YYYY-MM-DD'}, 400

        # Check if the book exists
        book = Book.query.get(book_id)
        if not book:
            return {'message': 'Book not found'}, 404

        # Check if the user exists
        if not user:
            return {'message': 'User not found'}, 404

        # Create the borrow history record
        borrow_history = BorrowHistory(
            book_id=book_id,
            user_id=user.id,
            start_date=start_date,
            end_date=end_date,
            return_date=return_date
        )

        # Add the new borrow history to the database
        db.session.add(borrow_history)
        db.session.commit()

        return {'message': 'Borrow history added successfully', 'borrow_history_id': borrow_history.id}, 201


# API to view personal book borrow history
@api.route('/api/my-history')
# class MyBorrowHistory(Resource):
#     @jwt_required()
#     def get(self):
#         """View personal book borrow history"""
#         current_user_email = get_jwt_identity()
#         user = User.query.filter_by(email=current_user_email).first()

#         # Get borrow history for the authenticated user
#         borrow_history = BorrowHistory.query.filter_by(user_id=user.id).all()
#         if not borrow_history:
#             return {'message': 'No borrow history found'}, 404
        
#         history_data = [
#             {
#                 'book_id': history.book_id,
#                 'start_date': history.start_date,
#                 'end_date': history.end_date,
#                 'return_date': history.return_date
#             }
#             for history in borrow_history
#         ]
#         return history_data
class MyBorrowHistory(Resource):
    @jwt_required()
    def get(self):
        """View personal book borrow history"""
        current_user_email = get_jwt_identity()
        user = User.query.filter_by(email=current_user_email).first()

        # Get borrow history for the authenticated user
        borrow_history = BorrowHistory.query.filter_by(user_id=user.id).all()
        if not borrow_history:
            return {'message': 'No borrow history found'}, 404
        
        # Convert date objects to string in 'YYYY-MM-DD' format
        history_data = [
            {
                'borrow_history_id': history.id,
                'book_id': history.book_id,
                'start_date': history.start_date.strftime('%Y-%m-%d') if history.start_date else None,
                'end_date': history.end_date.strftime('%Y-%m-%d') if history.end_date else None,
                'return_date': history.return_date.strftime('%Y-%m-%d') if history.return_date else None
            }
            for history in borrow_history
        ]
        
        return history_data


@api.route('/api/export/history')
# class ExportHistory(Resource):
#     @jwt_required()
#     def get(self):
#         """Export borrow history of the logged-in user as CSV"""
#         # Get the current logged-in user's email from JWT token
#         current_user_email = get_jwt_identity()
        
#         # Fetch the user from the database
#         user = User.query.filter_by(email=current_user_email).first()
        
#         # Query borrow history for the authenticated user
#         history = BorrowHistory.query.filter_by(user_id=user.id).all()
        
#         # Check if history exists
#         if not history:
#             return {'message': 'No borrow history found'}, 404
        
#         # Prepare a CSV file in memory
#         output = StringIO()
#         writer = csv.writer(output)
        
#         # Write header row to the CSV
#         writer.writerow(["Book ID", "Book Title", "Start Date", "End Date", "Return Date"])
        
#         # Write data rows
#         for borrow in history:
#             book = Book.query.get(borrow.book_id)
#             writer.writerow([book.id, book.title, borrow.start_date, borrow.end_date, borrow.return_date])
        
#         # Move the cursor to the beginning of the StringIO buffer
#         output.seek(0)
        
#         # Send the CSV as a downloadable file
#         return send_file(output, mimetype='text/csv', as_attachment=True, download_name='borrow_history.csv')
class ExportHistory(Resource):
    @jwt_required()
    def get(self):
        """Export borrow history of the logged-in user as CSV"""
        # Get the current logged-in user's email from JWT token
        current_user_email = get_jwt_identity()
        
        # Fetch the user from the database
        user = User.query.filter_by(email=current_user_email).first()
        
        # Query borrow history for the authenticated user
        history = BorrowHistory.query.filter_by(user_id=user.id).all()
        
        # Check if history exists
        if not history:
            return {'message': 'No borrow history found'}, 404
        
        # Prepare a CSV file in memory using BytesIO (binary mode)
        output = BytesIO()
        writer = csv.writer(output)
        
        # Write header row to the CSV
        writer.writerow(["Book ID", "Book Title", "Start Date", "End Date", "Return Date"])
        
        # Write data rows
        for borrow in history:
            book = Book.query.get(borrow.book_id)
            writer.writerow([book.id, book.title, borrow.start_date, borrow.end_date, borrow.return_date])
        
        # Move the cursor to the beginning of the BytesIO buffer
        output.seek(0)
        
        # Send the CSV as a downloadable file
        return send_file(output, mimetype='text/csv', as_attachment=True, download_name='borrow_history.csv')



# Start the Flask app
if __name__ == '__main__':
    app.run(debug=True)


