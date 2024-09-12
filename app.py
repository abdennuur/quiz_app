from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import random

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Set up the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz_app.db'
db = SQLAlchemy(app)

# Set up Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Question model
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_text = db.Column(db.String(255), nullable=False)
    option_1 = db.Column(db.String(100), nullable=False)
    option_2 = db.Column(db.String(100), nullable=False)
    option_3 = db.Column(db.String(100), nullable=False)
    option_4 = db.Column(db.String(100), nullable=False)
    correct_answer = db.Column(db.String(100), nullable=False)

# Quiz Result model
class QuizResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    score = db.Column(db.Integer)
    user = db.relationship('User', backref='results')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already taken, please choose another.')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password. Please try again.')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return f'Hello, {current_user.username}! <a href="/quiz">Start Quiz</a> | <a href="/logout">Logout</a>'

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/quiz', methods=['GET', 'POST'])
@login_required
def quiz():
    question_ids = [q.id for q in Question.query.all()]
    
    # Shuffle the questions to randomize
    random.shuffle(question_ids)
    
    # Save the randomized question order in the session
    session['questions'] = question_ids
    session['current_question'] = 0
    session['score'] = 0
    
    return redirect(url_for('quiz_question', question_number=1))

@app.route('/quiz_question/<int:question_number>', methods=['GET', 'POST'])
@login_required
def quiz_question(question_number):
    questions = session.get('questions')
    current_question_index = session.get('current_question', 0)
    
    if current_question_index >= len(questions):
        return redirect(url_for('quiz_results'))
    
    question = Question.query.get(questions[current_question_index])

    if request.method == 'POST':
        selected_answer = request.form.get('answer')
        if selected_answer == question.correct_answer:
            session['score'] = session.get('score', 0) + 1
        
        session['current_question'] += 1
        return redirect(url_for('quiz_question', question_number=question_number + 1))

    return render_template('quiz.html', question=question)

@app.route('/quiz_results')
@login_required
def quiz_results():
    score = session.get('score', 0)
    
    total_questions = len(session.get('questions', []))
    percentage = (score / total_questions) * 100 if total_questions > 0 else 0
    
    new_result = QuizResult(user_id=current_user.id, score=score)
    db.session.add(new_result)
    db.session.commit()

    session.pop('score', None)  # Clear the score from session

    return render_template('quiz_results.html', score=score, percentage=percentage, total_questions=total_questions)

# Admin Dashboard for managing questions
@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.username != 'admin':  # Restrict access to only admin
        return redirect(url_for('dashboard'))

    questions = Question.query.all()
    return render_template('admin_dashboard.html', questions=questions)

@app.route('/admin/add_question', methods=['GET', 'POST'])
@login_required
def add_question():
    if current_user.username != 'admin':
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        question_text = request.form['question_text']
        option_1 = request.form['option_1']
        option_2 = request.form['option_2']
        option_3 = request.form['option_3']
        option_4 = request.form['option_4']
        correct_answer = request.form['correct_answer']

        new_question = Question(
            question_text=question_text,
            option_1=option_1,
            option_2=option_2,
            option_3=option_3,
            option_4=option_4,
            correct_answer=correct_answer
        )
        db.session.add(new_question)
        db.session.commit()

        flash('Question added successfully!')
        return redirect(url_for('admin_dashboard'))

    return render_template('add_question.html')

@app.route('/admin/edit_question/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_question(id):
    if current_user.username != 'admin':
        return redirect(url_for('dashboard'))

    question = Question.query.get(id)
    if request.method == 'POST':
        question.question_text = request.form['question_text']
        question.option_1 = request.form['option_1']
        question.option_2 = request.form['option_2']
        question.option_3 = request.form['option_3']
        question.option_4 = request.form['option_4']
        question.correct_answer = request.form['correct_answer']

        db.session.commit()
        flash('Question updated successfully!')
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_question.html', question=question)

@app.route('/admin/delete_question/<int:id>', methods=['POST'])
@login_required
def delete_question(id):
    if current_user.username != 'admin':
        return redirect(url_for('dashboard'))

    question = Question.query.get(id)
    db.session.delete(question)
    db.session.commit()

    flash('Question deleted successfully!')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # This creates the database tables
    app.run(debug=True)
