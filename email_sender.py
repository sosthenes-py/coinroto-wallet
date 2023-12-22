import smtplib
from email.message import EmailMessage

SITE_DOMAIN = "192.168.216.231:5000"
SITE_NAME = "COINROTO"


class EmailSender:
    """
    All reasons expect email kwarg
    ...
    Registration requires the following kwargs:
    name (single name of user)
    code (UUID generated during registration)
    email (email address of user)
    """

    def __init__(self, reason, **kwargs):
        self.reason = reason
        self.kwargs = kwargs
        data = {
            "registration":
                {
                    "subject": f"Welcome to {SITE_NAME}!",
                },
            "action":
                {
                    "subject": f"Complete action on {SITE_NAME}!",
                }

        }
        self.use = data[self.reason]

        self.msg = EmailMessage()
        self.msg['Subject'] = self.use['subject']
        self.msg['From'] = f'{SITE_NAME} <mail@sosthenes.me>'
        self.msg.set_content(self.format_msg(), subtype="html")

    def send_email(self):
        self.msg['To'] = self.kwargs['email']
        with smtplib.SMTP_SSL("smtp.titan.email", 465) as conn:
            conn.login('mail@sosthenes.me', '07066452000Ss#')
            try:
                conn.send_message(self.msg)
            except:
                pass
                # raise 'Email could not be sent'

    def format_msg(self):
        if self.reason == "registration":
            return f"""
                    
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ccc;">

        <h2>Email Verification</h2>

        <p>Hello [Username],</p>

        <p>To complete your signp, please click on the button below to verify your email address:</p>

        <p style="text-align: center;">
            <a href="http://{SITE_DOMAIN}/verify-email?code={self.kwargs['code']}" style="display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: #fff; text-decoration: none; border-radius: 5px;">Authenticate</a>
        </p>

        <p>You have received this email because you created an account on {SITE_NAME}.</p>

        <p>Best regards,<br>Team</p>

    </div>
            """

        if self.reason == "action":
            return f"""

                     <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ccc;">

        <h2>Email Authentication</h2>

        <p>Hello,</p>

        <p>To authenticate your action, please click on the button below:</p>

        <p style="text-align: center;">
            <a href="http://{SITE_DOMAIN}/verify-email?code={self.kwargs['code']}" style="display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: #fff; text-decoration: none; border-radius: 5px;">Authenticate</a>
        </p>

        <p>If you didn't initiate this action, you can safely ignore this email.</p>

        <p>Best regards,<br>{SITE_NAME} Team</p>

    </div>
                        """
