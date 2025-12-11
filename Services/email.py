from typing import Dict

import resend

def send_mail(to:[str], subject:str, html:str) -> Dict:
    params: resend.Emails.SendParams = {
        "from": "welcome@jwt.knollfear.com",
        "to": to,
        "subject": subject,
        "html": html,
    }
    email: resend.Email = resend.Emails.send(params)
    return email