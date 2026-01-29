"""
smtp_handler.py - Gestionnaire SMTP Multi-Compte pour PhishShield
Utilise les 4 comptes Gmail en rotation pour envoyer les campagnes
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv
import logging
from datetime import datetime

load_dotenv()

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/smtp.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SMTPHandler:
    """Gestionnaire SMTP avec support multi-compte Gmail"""
    
    def __init__(self):
        """Initialise le gestionnaire avec les 4 comptes Gmail"""
        
        # Charger les 4 comptes depuis .env
        self.accounts = [
            {
                'email': os.getenv('SMTP_SENDER_1'),
                'password': os.getenv('SMTP_PASSWORD_1'),
                'index': 1
            },
            {
                'email': os.getenv('SMTP_SENDER_2'),
                'password': os.getenv('SMTP_PASSWORD_2'),
                'index': 2
            },
            {
                'email': os.getenv('SMTP_SENDER_3'),
                'password': os.getenv('SMTP_PASSWORD_3'),
                'index': 3
            },
            {
                'email': os.getenv('SMTP_SENDER_4'),
                'password': os.getenv('SMTP_PASSWORD_4'),
                'index': 4
            }
        ]
        
        self.smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', 465))
        self.current_account_index = 0
        
        logger.info("✓ SMTPHandler initialisé avec 4 comptes Gmail")
    
    def get_next_account(self):
        """Retourne le prochain compte en rotation"""
        account = self.accounts[self.current_account_index]
        self.current_account_index = (self.current_account_index + 1) % len(self.accounts)
        return account
    
    def send_email(self, recipient_email, subject, html_content, retry=0):
        """
        Envoie un email via un compte Gmail
        
        Args:
            recipient_email (str): Email du destinataire
            subject (str): Sujet de l'email
            html_content (str): Contenu HTML de l'email
            retry (int): Nombre de tentatives
        
        Returns:
            dict: {'success': bool, 'sender': str, 'error': str}
        """
        
        max_retries = int(os.getenv('SMTP_RETRY_COUNT', 3))
        
        # Obtenir le compte actuel
        account = self.get_next_account()
        sender_email = account['email']
        sender_password = account['password']
        
        try:
            # Vérifier les identifiants
            if not sender_email or not sender_password:
                error_msg = f"Identifiants manquants pour le compte {account['index']}"
                logger.error(error_msg)
                return {'success': False, 'sender': None, 'error': error_msg}
            
            # Créer le message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = sender_email
            msg['To'] = recipient_email
            msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S +0000')
            
            # Ajouter le contenu HTML
            msg.attach(MIMEText(html_content, 'html'))
            
            logger.info(f" Connexion à {self.smtp_server}:{self.smtp_port}")
            
            # Connexion au serveur SMTP avec timeout
            with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, timeout=10) as server:
                
                # Authentification
                logger.info(f" Authentification avec {sender_email}")
                server.login(sender_email, sender_password)
                
                # Envoi
                logger.info(f" Envoi de '{subject}' à {recipient_email}")
                server.sendmail(sender_email, recipient_email, msg.as_string())
                
                logger.info(f"✓ Email envoyé avec succès de {sender_email} vers {recipient_email}")
            
            return {
                'success': True,
                'sender': sender_email,
                'error': None
            }
        
        except smtplib.SMTPAuthenticationError as e:
            error_msg = f" Erreur d'authentification pour {sender_email}: {str(e)}"
            logger.error(error_msg)
            
            # Retry avec le compte suivant
            if retry < max_retries:
                logger.info(f"🔄 Tentative {retry + 1}/{max_retries}...")
                return self.send_email(recipient_email, subject, html_content, retry + 1)
            
            return {'success': False, 'sender': sender_email, 'error': error_msg}
        
        except smtplib.SMTPException as e:
            error_msg = f" Erreur SMTP: {str(e)}"
            logger.error(error_msg)
            
            # Retry
            if retry < max_retries:
                logger.info(f"🔄 Tentative {retry + 1}/{max_retries}...")
                return self.send_email(recipient_email, subject, html_content, retry + 1)
            
            return {'success': False, 'sender': sender_email, 'error': error_msg}
        
        except Exception as e:
            error_msg = f" Erreur inattendue: {str(e)}"
            logger.error(error_msg)
            
            # Retry
            if retry < max_retries:
                logger.info(f"🔄 Tentative {retry + 1}/{max_retries}...")
                return self.send_email(recipient_email, subject, html_content, retry + 1)
            
            return {'success': False, 'sender': sender_email, 'error': error_msg}
    
    def send_bulk_emails(self, recipients_emails, subject, html_content):
        """
        Envoie des emails en masse
        
        Args:
            recipients_emails (list): Liste des emails destinataires
            subject (str): Sujet
            html_content (str): Contenu HTML
        
        Returns:
            dict: Résumé des résultats
        """
        results = {
            'total': len(recipients_emails),
            'sent': 0,
            'failed': 0,
            'details': [],
            'errors': []
        }
        
        logger.info(f" Début envoi en masse vers {len(recipients_emails)} destinataires")
        
        for i, recipient in enumerate(recipients_emails, 1):
            try:
                logger.info(f"[{i}/{len(recipients_emails)}] Envoi à {recipient}...")
                
                result = self.send_email(recipient, subject, html_content)
                
                if result['success']:
                    results['sent'] += 1
                    results['details'].append({
                        'email': recipient,
                        'status': 'success',
                        'sender': result['sender']
                    })
                else:
                    results['failed'] += 1
                    results['errors'].append(result['error'])
                    results['details'].append({
                        'email': recipient,
                        'status': 'failed',
                        'error': result['error']
                    })
            
            except Exception as e:
                results['failed'] += 1
                error_msg = f"Exception pour {recipient}: {str(e)}"
                results['errors'].append(error_msg)
                logger.error(error_msg)
        
        logger.info(f"✓ Envoi terminé: {results['sent']}/{results['total']} réussis")
        return results


# Instance globale du gestionnaire
smtp_handler = SMTPHandler()