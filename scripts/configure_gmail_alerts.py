"""Local masked Gmail setup. Verifies SMTP authentication; never sends a message."""
from pathlib import Path
import re
import smtplib
import ssl
from email.utils import formataddr,parseaddr
from dotenv import dotenv_values,set_key

ROOT=Path(__file__).resolve().parents[1]



def authenticate_gmail_once(smtp,sender,password):
    """Preserve Gmail's first rejection instead of retrying another AUTH mechanism."""
    code,response=smtp.ehlo()
    if code!=250:
        raise smtplib.SMTPHeloError(code,response)
    if not smtp.has_extn('auth') or 'PLAIN' not in smtp.esmtp_features.get('auth','').upper().split():
        raise smtplib.SMTPNotSupportedError('Gmail did not advertise AUTH PLAIN after TLS')
    code,response=smtp.auth('PLAIN',lambda challenge=None:'\0'+sender+'\0'+password,initial_response_ok=False)
    if code not in (235,503):
        raise smtplib.SMTPAuthenticationError(code,response)


def verification_message(error):
    if isinstance(error,smtplib.SMTPAuthenticationError):
        if error.smtp_code==535:
            return 'Gmail rejected the sender credentials (SMTP 535). Check the Gmail address and use a Gmail-approved SMTP credential. No password was saved.'
        if error.smtp_code==534:
            return 'Gmail requires additional account authorization (SMTP 534). Check its app-password or Google sign-in requirements. No password was saved.'
        return 'Gmail rejected authentication. No password was saved; review the sender account settings.'
    if isinstance(error,smtplib.SMTPServerDisconnected):
        return 'Gmail closed the SMTP connection. This is separate from TestAPI. No password was saved.'
    if isinstance(error,(TimeoutError,OSError)):
        return 'Could not connect securely to Gmail SMTP. This is separate from TestAPI. No password was saved.'
    if isinstance(error,ValueError):
        return str(error)
    return 'Setup did not complete. Check private settings before retrying. No email was sent.'


def save_verified_settings(sender,recipient,password,*,display_name='ExtSecure',env_path=None,smtp_factory=None):
    sender=sender.strip();recipient=recipient.strip();display_name=display_name.strip()
    if not re.fullmatch(r'[A-Za-z0-9._%+-]+@gmail\.com',sender,re.I):
        raise ValueError('Use the Gmail account selected to send ExtSecure alerts.')
    if not recipient or any(c in recipient for c in '\r\n') or parseaddr(recipient)[1]!=recipient or '@' not in recipient:
        raise ValueError('Enter one valid administrator email address.')
    if not display_name or len(display_name)>80 or any(c in display_name for c in '\r\n'):
        raise ValueError('Enter a sender name without line breaks.')
    if not isinstance(password,str) or len(password)<6:
        raise ValueError('Enter an SMTP password with at least 6 characters. There is no application maximum.')
    factory=smtp_factory or smtplib.SMTP
    with factory('smtp.gmail.com',587,timeout=15) as smtp:
        smtp.starttls(context=ssl.create_default_context())
        authenticate_gmail_once(smtp,sender,password)
    path=Path(env_path) if env_path else ROOT/'.env'
    values={'ADMIN_EMAILS':recipient,'SMTP_HOST':'smtp.gmail.com','SMTP_PORT':'587',
            'SMTP_USERNAME':sender,'SMTP_FROM':formataddr((display_name,sender)),'SMTP_PASSWORD':password}
    for name,value in values.items():set_key(str(path),name,value)
    return {'verified':True,'display_name':display_name,'email_sent':False}


def main():
    import tkinter as tk
    from tkinter import ttk
    from threading import Thread
    values=dotenv_values(ROOT/'.env')
    root=tk.Tk();root.title('ExtSecure - private email setup');root.geometry('580x530');root.resizable(False,False)
    frame=ttk.Frame(root,padding=24);frame.pack(fill='both',expand=True)
    ttk.Label(frame,text='ExtSecure email alerts',font=('Segoe UI',16,'bold')).pack(anchor='w')
    ttk.Label(frame,text='Automatic Gmail delivery: authorize ExtSecure with a Google app password.',wraplength=485).pack(anchor='w',pady=(6,14))
    sender=tk.StringVar(value=values.get('SMTP_USERNAME',''))
    recipient=tk.StringVar(value=values.get('ADMIN_EMAILS',''))
    password=tk.StringVar()
    for label,var,masked in [('Sender Gmail account',sender,False),('Administrator recipient',recipient,False),('Google app password (not your Gmail sign-in password)',password,True)]:
        ttk.Label(frame,text=label).pack(anchor='w')
        ttk.Entry(frame,textvariable=var,show='*' if masked else '').pack(fill='x',pady=(2,9))
    ttk.Label(frame,text='1. Enable Google two-step verification.\n2. Generate an app password named ExtSecure.\n3. Enter it above and verify. Sender name: ExtSecure.\nCredentials stay in private server configuration, never in the extension.',wraplength=485).pack(anchor='w')
    import webbrowser
    ttk.Button(frame,text='Open Google app passwords',command=lambda:webbrowser.open('https://myaccount.google.com/apppasswords')).pack(anchor='w',pady=(8,0))
    status=tk.StringVar(value='Waiting for Gmail authorization. Verification does not send an email.')
    ttk.Label(frame,textvariable=status,wraplength=485).pack(anchor='w',pady=(12,8))
    def save():
        submitted=(sender.get(),recipient.get(),password.get())
        button.configure(state='disabled');status.set('Verifying Gmail authentication...')
        def work():
            try:
                save_verified_settings(*submitted)
                message='Verified and saved. Restart TestAPI to apply email settings. No email was sent.'
            except Exception as error:message=verification_message(error)
            def done():
                password.set('');status.set(message);button.configure(state='normal')
            root.after(0,done)
        Thread(target=work,daemon=True).start()
    button=ttk.Button(frame,text='Verify and save privately',command=save);button.pack(anchor='w')
    root.mainloop()


if __name__=='__main__':main()
