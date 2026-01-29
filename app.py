from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import os
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sqlite3
import uuid
import logging
from logging.handlers import RotatingFileHandler

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-this')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishing_platform.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
CORS(app)

# Configuration logging
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/phishing_platform.log', maxBytes=10240000, backupCount=10)
file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

# ==================== MODÈLES ====================
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    users = db.relationship('User', backref='role')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    security_level = db.Column(db.Integer, default=50)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    def set_password(self, password):
        self.password = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password, password)

class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    launch_date = db.Column(db.DateTime)
    email_template = db.Column(db.Text)
    phishing_url = db.Column(db.String(255))
    emails = db.relationship('Email', backref='campaign', lazy=True, cascade='all, delete-orphan')
    
    creator = db.relationship('User', backref='campaigns')

class Email(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    opened = db.Column(db.Boolean, default=False)
    opened_at = db.Column(db.DateTime)
    tracking_token = db.Column(db.String(255), unique=True, default=lambda: str(uuid.uuid4()))
    
    recipient = db.relationship('User', backref='received_emails')

class Click(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email_id = db.Column(db.Integer, db.ForeignKey('email.id'))
    clicked_at = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    
    email = db.relationship('Email', backref='clicks')

class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    questions = db.Column(db.Text)  # JSON
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class QuizResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'))
    score = db.Column(db.Integer)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='quiz_results')
    quiz = db.relationship('Quiz')

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(255))
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='audit_logs')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role.name != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        return f(*args, **kwargs)
    return decorated_function

def log_audit(user_id, action, details, ip_address):
    log = AuditLog(user_id=user_id, action=action, details=details, ip_address=ip_address)
    db.session.add(log)
    db.session.commit()
    app.logger.info(f"AUDIT: {action} by user {user_id} - {details}")

# ==================== ROUTES ====================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            log_audit(user.id, 'LOGIN', 'User login', request.remote_addr)
            return jsonify({'success': True, 'role': user.role.name}), 200
        
        log_audit(None, 'FAILED_LOGIN', f'Failed login attempt for {username}', request.remote_addr)
        return jsonify({'error': 'Invalid credentials'}), 401
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_audit(current_user.id, 'LOGOUT', 'User logout', request.remote_addr)
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/employee/dashboard')
@login_required
def employee_dashboard():
    if current_user.role.name != 'user':
        return redirect(url_for('admin_dashboard'))
    return render_template('employee_dashboard.html')

@app.route('/api/dashboard/stats')
@login_required
@admin_required
def get_stats():
    total_campaigns = Campaign.query.count()
    total_emails_sent = Email.query.count()
    total_opened = Email.query.filter_by(opened=True).count()
    total_clicks = Click.query.count()
    
    open_rate = (total_opened / total_emails_sent * 100) if total_emails_sent > 0 else 0
    click_rate = (total_clicks / total_emails_sent * 100) if total_emails_sent > 0 else 0
    
    # Données hebdomadaires
    week_ago = datetime.utcnow() - timedelta(days=7)
    weekly_emails = Email.query.filter(Email.sent_at >= week_ago).count()
    weekly_clicks = Click.query.filter(Click.clicked_at >= week_ago).count()
    
    return jsonify({
        'totalCampaigns': total_campaigns,
        'totalEmailsSent': total_emails_sent,
        'totalOpened': total_opened,
        'totalClicks': total_clicks,
        'openRate': round(open_rate, 2),
        'clickRate': round(click_rate, 2),
        'weeklyEmails': weekly_emails,
        'weeklyClicks': weekly_clicks
    })

@app.route('/api/dashboard/timeline')
@login_required
@admin_required
def get_timeline():
    last_7_days = []
    for i in range(7):
        date = datetime.utcnow().date() - timedelta(days=i)
        date_str = date.strftime('%Y-%m-%d')
        emails = Email.query.filter(
            db.func.date(Email.sent_at) == date
        ).count()
        clicks = Click.query.filter(
            db.func.date(Click.clicked_at) == date
        ).count()
        last_7_days.append({
            'date': date_str,
            'emails': emails,
            'clicks': clicks
        })
    
    return jsonify(last_7_days[::-1])

@app.route('/api/dashboard/user-security')
@login_required
@admin_required
def get_user_security():
    users = User.query.filter(User.role_id != 1).all()
    return jsonify([{
        'username': u.username,
        'securityLevel': u.security_level,
        'email': u.email
    } for u in users])

@app.route('/api/dashboard/logs')
@login_required
@admin_required
def get_logs():
    page = request.args.get('page', 1, type=int)
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=20)
    
    return jsonify({
        'logs': [{
            'id': log.id,
            'user': log.user.username if log.user else 'System',
            'action': log.action,
            'details': log.details,
            'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'ip': log.ip_address
        } for log in logs.items],
        'total': logs.total
    })

@app.route('/api/campaigns', methods=['GET', 'POST'])
@login_required
@admin_required
def campaigns():
    if request.method == 'POST':
        data = request.get_json()
        campaign = Campaign(
            name=data['name'],
            description=data['description'],
            created_by=current_user.id,
            email_template=data['template'],
            phishing_url=data['phishing_url']
        )
        db.session.add(campaign)
        db.session.commit()
        log_audit(current_user.id, 'CREATE_CAMPAIGN', f'Created campaign: {campaign.name}', request.remote_addr)
        return jsonify({'success': True, 'id': campaign.id}), 201
    
    campaigns = Campaign.query.all()
    return jsonify([{
        'id': c.id,
        'name': c.name,
        'created_at': c.created_at.strftime('%Y-%m-%d'),
        'emails_sent': len(c.emails)
    } for c in campaigns])

@app.route('/api/campaigns/<int:campaign_id>/send', methods=['POST'])
@login_required
@admin_required
def send_campaign(campaign_id):
    campaign = Campaign.query.get(campaign_id)
    if not campaign:
        return jsonify({'error': 'Campaign not found'}), 404
    
    data = request.get_json()
    recipients = data.get('recipients', [])
    
    email_config = {
        'kadygakchaichi@gmail.com': 'fspt ywfh gdrz ozge',
        'iconomistlamia@gmail.com': 'zprn kusn lvfh agbn',
        'bzouhaier344@gmail.com': 'xsod npms qvaz xnsw',
        'chaimaayed45111@gmail.com': 'pmpo pvee oxn odfh'
    }
    
    sender_email = list(email_config.keys())[0]
    sender_password = email_config[sender_email]
    
    for recipient_username in recipients:
        user = User.query.filter_by(username=recipient_username).first()
        if not user:
            continue
        
        email_obj = Email(campaign_id=campaign_id, user_id=user.id)
        db.session.add(email_obj)
        db.session.flush()
        
        tracking_url = f"{request.host_url}track/{email_obj.tracking_token}"
        html_content = campaign.email_template.replace('[TRACKING_URL]', tracking_url)
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"Security Alert - Action Required"
            msg['From'] = sender_email
            msg['To'] = user.email
            
            msg.attach(MIMEText(html_content, 'html'))
            
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, user.email, msg.as_string())
            
            email_obj.sent_at = datetime.utcnow()
            db.session.commit()
        except Exception as e:
            app.logger.error(f"Failed to send email: {str(e)}")
    
    log_audit(current_user.id, 'SEND_CAMPAIGN', f'Sent campaign {campaign.name} to {len(recipients)} users', request.remote_addr)
    return jsonify({'success': True, 'sent': len(recipients)})

@app.route('/track/<token>')
def track_email(token):
    email = Email.query.filter_by(tracking_token=token).first()
    if email:
        email.opened = True
        email.opened_at = datetime.utcnow()
        
        click = Click(
            email_id=email.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        db.session.add(click)
        db.session.commit()
        
        app.logger.info(f"Email opened by user {email.user_id}")
    
    return redirect('/')

@app.route('/api/quizzes', methods=['GET', 'POST'])
@login_required
def quizzes():
    if request.method == 'POST' and current_user.role.name == 'admin':
        data = request.get_json()
        quiz = Quiz(title=data['title'], questions=data['questions'])
        db.session.add(quiz)
        db.session.commit()
        return jsonify({'success': True, 'id': quiz.id}), 201
    
    quizzes = Quiz.query.all()
    return jsonify([{
        'id': q.id,
        'title': q.title,
        'questions': q.questions,
        'created_at': q.created_at.strftime('%Y-%m-%d')
    } for q in quizzes])

@app.route('/api/quizzes/<int:quiz_id>/submit', methods=['POST'])
@login_required
def submit_quiz(quiz_id):
    data = request.get_json()
    score = data.get('score', 0)
    
    quiz_result = QuizResult(
        user_id=current_user.id,
        quiz_id=quiz_id,
        score=score
    )
    db.session.add(quiz_result)
    
    current_user.security_level = min(100, current_user.security_level + 5)
    db.session.commit()
    
    log_audit(current_user.id, 'QUIZ_COMPLETED', f'Completed quiz {quiz_id} with score {score}', request.remote_addr)
    
    return jsonify({'success': True, 'newLevel': current_user.security_level})

@app.route('/api/quiz/results', methods=['GET'])
@login_required
def get_quiz_results():
    """Récupère les résultats de quiz de l'utilisateur connecté"""
    results = QuizResult.query.filter_by(user_id=current_user.id).order_by(QuizResult.completed_at.desc()).all()
    
    return jsonify([{
        'id': r.id,
        'quiz_id': r.quiz_id,
        'quiz_title': r.quiz.title,
        'score': r.score,
        'completed_at': r.completed_at.isoformat()
    } for r in results])

@app.route('/api/admin/quiz/results', methods=['GET'])
@login_required
@admin_required
def get_all_quiz_results():
    """Récupère tous les résultats de quiz (pour l'admin)"""
    results = QuizResult.query.order_by(QuizResult.completed_at.desc()).all()
    
    return jsonify([{
        'id': r.id,
        'user_id': r.user_id,
        'username': r.user.username,
        'quiz_id': r.quiz_id,
        'quiz_title': r.quiz.title,
        'score': r.score,
        'completed_at': r.completed_at.isoformat()
    } for r in results])

@app.route('/api/quiz/notify-users', methods=['POST'])
@login_required
@admin_required
def notify_quiz_users():
    """Envoie les notifications de quiz aux utilisateurs"""
    data = request.get_json()
    quiz_id = data.get('quiz_id')
    users = data.get('users', [])
    
    app.logger.info(f"QUIZ NOTIFICATION: Received request for quiz_id={quiz_id}, users={len(users)}")
    
    quiz = Quiz.query.get(quiz_id)
    if not quiz:
        app.logger.error(f"Quiz {quiz_id} not found")
        return jsonify({'error': 'Quiz not found'}), 404
    
    # Configuration email
    email_config = {
        'kadygakchaichi@gmail.com': 'ftpt ywfh spjy abch',
        'iconomistlamia@gmail.com': 'mrhy kusn lvfh gbhe',
        'bzouhaier344@gmail.com': 'hjum ekue qvdt asez',
        'chaimaayed45111@gmail.com': 'frnb pvee naxs cdea'
    }
    
    sender_email = list(email_config.keys())[0]
    sender_password = email_config[sender_email]
    
    sent_count = 0
    
    for user_data in users:
        user_email = user_data.get('email')
        username = user_data.get('username')
        
        if not user_email:
            app.logger.warning(f"No email for user {username}")
            continue
        
        # Créer le contenu de l'email avec identifiants
        html_content = f"""
        <html>
        <head>
            <meta charset="UTF-8">
        </head>
        <body style="font-family: Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 0;">
            <div style="max-width: 600px; margin: 20px auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <h2 style="color: #00c8ff; margin-top: 0;">📚 Nouveau Quiz Disponible</h2>
                <p style="color: #333; font-size: 14px;">Bonjour <strong>{username}</strong>,</p>
                
                <p style="color: #333; font-size: 14px;">Un nouveau quiz a été assigné pour vous:</p>
                
                <div style="background: #f0f0f0; padding: 15px; border-left: 4px solid #00c8ff; margin: 20px 0; border-radius: 4px;">
                    <h3 style="margin: 0 0 10px 0; color: #333;">📖 {quiz.title}</h3>
                    <p style="color: #666; font-size: 14px; margin: 0;">Complétez ce quiz pour améliorer votre niveau de sécurité.</p>
                </div>
                
                <div style="background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0; border-radius: 4px;">
                    <h4 style="margin: 0 0 10px 0; color: #856404;">🔐 Vos identifiants:</h4>
                    <p style="margin: 5px 0; color: #856404; font-size: 13px;">
                        <strong>Nom d'utilisateur:</strong> <code style="background: #fff; padding: 2px 6px; border-radius: 3px;">{username}</code>
                    </p>
                    <p style="margin: 5px 0; color: #856404; font-size: 13px;">
                        <strong>Email:</strong> <code style="background: #fff; padding: 2px 6px; border-radius: 3px;">{user_email}</code>
                    </p>
                </div>
                
                <p style="margin-top: 30px; text-align: center;">
                    <a href="http://127.0.0.1:5000/login" 
                       style="display: inline-block; background: #00c8ff; color: white; padding: 12px 30px; 
                              text-decoration: none; border-radius: 4px; font-weight: bold; font-size: 14px;">
                        🚀 Me Connecter
                    </a>
                </p>
                
                <p style="color: #666; font-size: 13px; margin-top: 20px; text-align: center;">
                    <strong>Étapes:</strong><br>
                    1️⃣ Connectez-vous avec vos identifiants ci-dessus<br>
                    2️⃣ Allez à "Mon Espace" → "Mes Quizzes"<br>
                    3️⃣ Complétez le quiz
                </p>
                
                <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
                <p style="color: #999; font-size: 12px; text-align: center; margin: 0;">
                    Ceci est une notification automatique de PhishShield.
                </p>
            </div>
        </body>
        </html>
        """
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"📚 {quiz.title} - Vous devez compléter ce quiz"
            msg['From'] = sender_email
            msg['To'] = user_email
            
            msg.attach(MIMEText(html_content, 'html'))
            
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, user_email, msg.as_string())
            
            sent_count += 1
            app.logger.info(f"✓ Quiz notification sent: {quiz.title} -> {user_email}")
            
        except Exception as e:
            app.logger.error(f"✗ Failed to send quiz notification to {user_email}: {str(e)}")
    
    log_audit(current_user.id, 'SEND_QUIZ', f'Sent quiz {quiz.title} to {sent_count} users', request.remote_addr)
    app.logger.info(f"QUIZ NOTIFICATION COMPLETE: {sent_count} emails sent")
    
    return jsonify({'success': True, 'sent': sent_count})

@app.route('/api/user/profile')
@login_required
def user_profile():
    return jsonify({
        'username': current_user.username,
        'email': current_user.email,
        'role': current_user.role.name,
        'securityLevel': current_user.security_level,
        'lastLogin': current_user.last_login.strftime('%Y-%m-%d %H:%M:%S') if current_user.last_login else None
    })

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(error):
    app.logger.error(f'Server error: {error}')
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)