from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

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
    return "Welcome to the Quiz App! <a href='/login'>Login</a> or <a href='/register'>Register</a> to start."

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Create new user
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return f'Hello, {current_user.username}! <a href="/quiz/1">Start Quiz</a> | <a href="/logout">Logout</a>'

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/quiz/<int:question_id>', methods=['GET', 'POST'])
@login_required
def quiz(question_id):
    question = Question.query.get(question_id)
    if question is None:
        return redirect(url_for('quiz_results'))  # Redirect to results when done

    if request.method == 'POST':
        selected_answer = request.form.get('answer')
        if selected_answer == question.correct_answer:
            session['score'] = session.get('score', 0) + 1  # Increment score in session

        # Move to the next question
        return redirect(url_for('quiz', question_id=question_id + 1))

    return render_template('quiz.html', question=question)

@app.route('/quiz_results')
@login_required
def quiz_results():
    score = session.get('score', 0)
    new_result = QuizResult(user_id=current_user.id, score=score)
    db.session.add(new_result)
    db.session.commit()

    session.pop('score', None)  # Clear the score from the session after saving
    return f'Your score: {score} <br> <a href="/dashboard">Back to Dashboard</a>'

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # This creates the database tables
    app.run(debug=True)

