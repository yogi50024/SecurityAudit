"""
Email Alert Module

Sends security report summaries to configured recipients using SMTP.
"""

import smtplib
from email.mime.text import MIMEText

def send_email_alert(report, to_email, subject="Security Audit Alert", smtp_server="localhost"):
    """
    Sends the report text as an email.
    """
    msg = MIMEText(report)
    msg['Subject'] = subject
    msg['From'] = "security-audit@yourdomain.com"
    msg['To'] = to_email

    with smtplib.SMTP(smtp_server) as server:
        server.send_message(msg)
