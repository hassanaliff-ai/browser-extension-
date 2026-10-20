"""Local Google sign-in setup for the ExtSecure server. No Gmail password entry."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))


def main():
    import tkinter as tk
    from tkinter import ttk, filedialog
    from threading import Thread
    import webbrowser
    from dotenv import load_dotenv, dotenv_values, set_key
    from alba_security.gmail_oauth import authorize, GmailAuthorizationError

    load_dotenv(ROOT / '.env', override=True)
    values = dotenv_values(ROOT / '.env')
    root = tk.Tk()
    root.title('ExtSecure - Sign in with Google')
    root.geometry('620x490')
    root.resizable(False, False)
    frame = ttk.Frame(root, padding=24)
    frame.pack(fill='both', expand=True)
    ttk.Label(frame, text='Connect Gmail to ExtSecure', font=('Segoe UI', 17, 'bold')).pack(anchor='w')
    ttk.Label(frame, text='Sign in on Google’s page. ExtSecure never asks for your Gmail password.\nAuthorize sending once so the server can send alerts and reports in the background.', wraplength=560).pack(anchor='w', pady=(10,16))
    client_path = tk.StringVar()
    recipient = tk.StringVar(value=values.get('ADMIN_EMAILS', ''))
    ttk.Label(frame, text='One-time setup: Google Desktop app OAuth client JSON').pack(anchor='w')
    ttk.Entry(frame, textvariable=client_path).pack(fill='x', pady=6)
    ttk.Button(frame, text='Choose client JSON', command=lambda: client_path.set(filedialog.askopenfilename(filetypes=[('Google client', '*.json')]) or client_path.get())).pack(anchor='w')
    ttk.Button(frame, text='Open Google Cloud setup', command=lambda: webbrowser.open('https://console.cloud.google.com/auth/clients')).pack(anchor='w', pady=(5,12))
    ttk.Label(frame, text='Administrator recipient email').pack(anchor='w')
    ttk.Entry(frame, textvariable=recipient).pack(fill='x', pady=6)
    status = tk.StringVar(value='Waiting for OAuth client. No email will be sent during authorization.')
    ttk.Label(frame, textvariable=status, wraplength=560).pack(anchor='w', pady=12)

    def sign_in():
        selected, destination = client_path.get().strip(), recipient.get().strip()
        if not selected:
            status.set('Choose the Desktop app client JSON first. See the setup guide for Google Cloud steps.')
            return
        button.configure(state='disabled')
        status.set('Complete sign-in and consent in your browser. Waiting up to five minutes…')

        def work():
            try:
                authorize(selected, destination)
                set_key(str(ROOT / '.env'), 'EMAIL_PROVIDER', 'gmail_oauth')
                message = 'Google connected. Restart TestAPI to activate Gmail sending. No email has been sent.'
            except GmailAuthorizationError as error:
                message = str(error)
            except Exception:
                message = 'Google setup could not finish. Check connectivity and the Desktop OAuth client. No Gmail password was stored.'
            root.after(0, lambda: finish(message))

        Thread(target=work, daemon=True).start()

    def finish(message):
        status.set(message)
        button.configure(state='normal')

    button = ttk.Button(frame, text='Sign in with Google', command=sign_in)
    button.pack(anchor='w', pady=8)
    root.mainloop()


if __name__ == '__main__':
    main()
