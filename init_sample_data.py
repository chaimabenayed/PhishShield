#!/usr/bin/env python3
"""
Script d'initialisation de la plateforme PhishShield
Crée les rôles, utilisateurs, quizzes et données de test
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, User, Role, Quiz, Campaign, Email, Click, QuizResult
from datetime import datetime, timedelta
import json

def init_database():
    """Initialise la base de données"""
    with app.app_context():
        print("🗄️  Création des tables...")
        db.create_all()
        print("✓ Tables créées avec succès")

def create_roles():
    """Crée les rôles"""
    with app.app_context():
        admin_role = Role.query.filter_by(name='admin').first()
        user_role = Role.query.filter_by(name='user').first()
        
        if not admin_role:
            admin_role = Role(name='admin')
            db.session.add(admin_role)
            print("✓ Rôle 'admin' créé")
        
        if not user_role:
            user_role = Role(name='user')
            db.session.add(user_role)
            print("✓ Rôle 'user' créé")
        
        db.session.commit()

def create_users():
    """Crée les utilisateurs"""
    with app.app_context():
        admin_role = Role.query.filter_by(name='admin').first()
        user_role = Role.query.filter_by(name='user').first()
        
        #  REMPLACEZ CES EMAILS PAR VOS EMAILS RÉELS POUR RECEVOIR LES CAMPAGNES
        users_data = [
            {
                'username': 'admin_security',
                'email': 'admin@phishshield.io',
                'password': 'AdminSecure123!',
                'role': admin_role,
                'security_level': 95
            },
            {
                'username': 'Khadija',
                'email': 'kadygakchaichi@gmail.com',  # ⬅️ EMAIL RÉEL (recevra les campagnes)
                'password': 'Khadija123!',
                'role': user_role,
                'security_level': 65
            },
            {
                'username': 'Lamia',
                'email': 'iconomistlamia@gmail.com',  #  EMAIL RÉEL
                'password': 'Lamia123!',
                'role': user_role,
                'security_level': 45
            },
            {
                'username': 'Zouhaier',
                'email': 'bzouhaier344@gmail.com',  #  EMAIL RÉEL
                'password': 'Zouhaier123!',
                'role': user_role,
                'security_level': 75
            },
            {
                'username': 'Chaima',
                'email': 'chaimaayed45111@gmail.com',  #  EMAIL RÉEL
                'password': 'Chaima123!',
                'role': user_role,
                'security_level': 55
            },
            {
                'username': 'Karima',
                'email': 'Karima.test@company.com',
                'password': 'Karima123!',
                'role': user_role,
                'security_level': 80
            },
        
        ]
        
        for user_data in users_data:
            existing = User.query.filter_by(username=user_data['username']).first()
            if not existing:
                user = User(
                    username=user_data['username'],
                    email=user_data['email'],
                    role_id=user_data['role'].id,
                    security_level=user_data['security_level']
                )
                user.set_password(user_data['password'])
                db.session.add(user)
                print(f"✓ Utilisateur '{user_data['username']}' créé")
                print(f"   Email: {user_data['email']}")
        
        db.session.commit()

def create_quizzes():
    """Crée les quizzes"""
    with app.app_context():
        quiz_data = [
            {
                'title': 'Quiz Phishing Débutant',
                'questions': json.dumps([
                    {
                        'id': 1,
                        'question': 'Quel est le principal indicateur d\'un email de phishing?',
                        'options': [
                            'Adresse email suspecte ou mal orthographiée',
                            'Demande urgente de confirmation de données',
                            'Lien qui ne correspond pas au texte affiché',
                            'Toutes les réponses'
                        ],
                        'correct': 3
                    },
                    {
                        'id': 2,
                        'question': 'Que faut-il vérifier avant de cliquer sur un lien?',
                        'options': [
                            'La couleur du lien',
                            'L\'adresse réelle en survolant le lien',
                            'La taille de la police',
                            'Le format du texte'
                        ],
                        'correct': 1
                    },
                    {
                        'id': 3,
                        'question': 'Que ne devriez-vous jamais faire?',
                        'options': [
                            'Cliquer sur des liens non vérifiés',
                            'Entrer vos identifiants sur un site non sécurisé',
                            'Consulter votre email professionnel',
                            'Lire vos emails régulièrement'
                        ],
                        'correct': 0
                    }
                ])
            },
            {
                'title': 'Quiz Phishing Intermédiaire',
                'questions': json.dumps([
                    {
                        'id': 1,
                        'question': 'Qu\'est-ce que le spear phishing?',
                        'options': [
                            'Un email de phishing généralisé',
                            'Une attaque ciblée vers une personne spécifique',
                            'Un virus informatique',
                            'Une arnaque téléphonique'
                        ],
                        'correct': 1
                    },
                    {
                        'id': 2,
                        'question': 'Comment vérifier si un site est sécurisé?',
                        'options': [
                            'Vérifier la présence du cadenas et "https"',
                            'Vérifier le nombre de visiteurs',
                            'Vérifier les couleurs du site',
                            'Consulter les avis utilisateurs'
                        ],
                        'correct': 0
                    }
                ])
            }
        ]
        
        for q_data in quiz_data:
            existing = Quiz.query.filter_by(title=q_data['title']).first()
            if not existing:
                quiz = Quiz(title=q_data['title'], questions=q_data['questions'])
                db.session.add(quiz)
                print(f"✓ Quiz '{q_data['title']}' créé")
        
        db.session.commit()

def create_sample_campaign():
    """Crée une campagne d'exemple"""
    with app.app_context():
        admin = User.query.filter_by(username='admin_security').first()
        
        existing = Campaign.query.filter_by(name='Campagne Test Q1 2024').first()
        if not existing:
            campaign = Campaign(
                name='Campagne Test Q1 2024',
                description='Campagne de sensibilisation au phishing pour le Q1',
                created_by=admin.id,
                email_template="""
<html>
<body style="font-family: Arial, sans-serif; background-color: #f5f5f5;">
    <div style="max-width: 600px; margin: 20px auto; background-color: white; padding: 20px; border-radius: 8px;">
        <h2 style="color: #333;">🔒 Alerte de Sécurité Importante</h2>
        <p>Votre compte nécessite une vérification urgente.</p>
        <p>Cliquez sur le lien ci-dessous pour confirmer votre identité:</p>
        <a href="[TRACKING_URL]" style="display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; font-weight: bold;">
            ✓ Vérifier mon compte
        </a>
        <p style="margin-top: 20px; font-size: 12px; color: #666;">
            Si vous n'avez pas demandé cette vérification, ignorez cet email.
        </p>
    </div>
</body>
</html>
                """,
                phishing_url='https://phishing-example.com',
                launch_date=datetime.utcnow()
            )
            db.session.add(campaign)
            print("✓ Campagne d'exemple créée")
            db.session.flush()
            
            users = User.query.filter(User.role.has(name='user')).all()
            for user in users[:4]:
                email = Email(campaign_id=campaign.id, user_id=user.id)
                db.session.add(email)
            
            db.session.commit()

def create_sample_quiz_results():
    """Crée des résultats de quiz d'exemple"""
    with app.app_context():
        users = User.query.filter(User.role.has(name='user')).all()
        quizzes = Quiz.query.all()
        
        for user in users[:4]:
            for quiz in quizzes:
                existing = QuizResult.query.filter_by(
                    user_id=user.id,
                    quiz_id=quiz.id
                ).first()
                
                if not existing:
                    score = 75 + (user.id * 5) % 25
                    result = QuizResult(
                        user_id=user.id,
                        quiz_id=quiz.id,
                        score=score,
                        completed_at=datetime.utcnow() - timedelta(days=5)
                    )
                    db.session.add(result)
            
            db.session.commit()
        
        print("✓ Résultats de quiz créés")

def main():
    """Fonction principale"""
    print("\n" + "="*60)
    print("  🛡️  INITIALISATION DE PhishShield")
    print("="*60 + "\n")
    
    try:
        init_database()
        create_roles()
        create_users()
        create_quizzes()
        create_sample_campaign()
        create_sample_quiz_results()
        
        print("\n" + "="*60)
        print("   INITIALISATION RÉUSSIE")
        print("="*60)
        print("\n Identifiants Admin:")
        print("   Utilisateur: admin_security")
        print("   Mot de passe: AdminSecure123!")
        print("\n Utilisateurs de Test Créés:")
        print("   • Khadija (kadygakchaichi@gmail.com)")
        print("   • Lamia (iconomistlamia@gmail.com)")
        print("   • Zouhaier (bzouhaier344@gmail.com)")
        print("   • Chaima (chaimaayed45111@gmail.com)")
        print("   • Karima (Karima.test@company.com)")
        print("\n Lancer l'application:")
        print("   python app.py")
        print("\n Accédez à:")
        print("   http://localhost:5000")
        print("   http://localhost:5000/login")
        print()
        
    except Exception as e:
        print(f"\n Erreur lors de l'initialisation: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()