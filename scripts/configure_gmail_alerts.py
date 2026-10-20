"""Local masked Gmail setup. Verifies SMTP authentication; never sends a message."""
from pathlib import Path
import re
import smtplib
import ssl
from email.utils import formataddr,parseaddr
from dotenv import dotenv_values,set_key

ROOT=Path(__file__).resolve().parents[1]


def save_verified_settings(sender,recipient,password,*,display_name='ExtSecure',env_path=None,smtp_factory=None):
    sender=sender.strip();recipient=recipient.strip();display_name=display_name.strip()
    password=''.join(password.split())
    if not re.fullmatch(r'[A-Za-z0-9._%+-]+@gmail\.com',sender,re.I):
        raise ValueError('Use the Gmail account selected to send ExtSecure alerts.')
    if not recipient or any(c in recipient for c in '\r\n') or parseaddr(recipient)[1]!=recipient or '@' not in recipient:
        raise ValueError('Enter one valid administrator email address.')
    if not display_name or len(display_name)>80 or any(c in display_name for c in '\r\n'):
        raise ValueError('Enter a sender name without line breaks.')
    if not re.fullmatch(r'[A-Za-z0-9]{16}',password):
        raise ValueError('Enter the 16-character Gmail app password, not your normal password.')
    factory=smtp_factory or smtplib.SMTP
    with factory('smtp.gmail.com',587,timeout=15) as smtp:
        smtp.starttls(context=ssl.create_default_context())
        smtp.login(sender,password)
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
    root=tk.Tk();root.title('ExtSecure â€” private email setup');root.geometry('540x410');root.resizable(False,False)
    frame=ttk.Frame(root,padding=24);frame.pack(fill='both',expand=True)
    ttk.Label(frame,text='ExtSecure email alerts',font=('Segoe UI',16,'bold')).pack(anchor='w')
    ttk.Label(frame,text='Verify the Gmail sender without sending any email.',wraplength=485).pack(anchor='w',pady=(6,14))
    sender=tk.StringVar(value=values.get('SMTP_USERNAME',''))
    recipient=tk.StringVar(value=values.get('ADMIN_EMAILS',''))
    password=tk.StringVar()
    for label,var,masked in [('Sender Gmail account',sender,False),('Administrator recipient',recipient,False),('Gmail app password â€” 16 characters',password,True)]:
        ttk.Label(frame,text=label).pack(anchor='w')
        ttk.Entry(frame,textvariable=var,show='*' if masked else '').pack(fill='x',pady=(2,9))
    ttk.Label(frame,text='Sender name: ExtSecure. Do not paste your normal Gmail password.\nThe app password stays in private local server configuration.',wraplength=485).pack(anchor='w')
    status=tk.StringVar(value='App password required. No password is shown in chat or GitHub.')
    ttk.Label(frame,textvariable=status,wraplength=485).pack(anchor='w',pady=(12,8))
    def save():
        submitted=(sender.get(),recipient.get(),password.get())
        button.configure(state='disabled');status.set('Verifying Gmail authenticationâ€¦')
        def work():
            try:
                save_verified_settings(*submitted)
                message='Verified and saved. Restart TestAPI to apply email settings. No email was sent.'
            except ValueError as error:message=str(error)
            except smtplib.SMTPAuthenticationError:message='Gmail rejected authentication. Use an app password from this sender account.'
            except Exception:message='Could not verify or save settings. Check the connection and try again.'
            def done():
                password.set('');status.set(message);button.configure(state='normal')
            root.after(0,done)
        Thread(target=work,daemon=True).start()
    button=ttk.Button(frame,text='Verify and save privately',command=save);button.pack(anchor='w')
    root.mainloop()


if __name__=='__main__':main()
