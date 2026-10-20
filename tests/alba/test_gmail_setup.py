"""No real email is sent and no production settings are read or written."""
import smtplib
from unittest.mock import MagicMock
import pytest
from dotenv import dotenv_values
from scripts.configure_gmail_alerts import save_verified_settings


def test_gmail_setup_verifies_tls_and_login_without_sending(tmp_path):
    factory=MagicMock();smtp=factory.return_value.__enter__.return_value
    path=tmp_path/'.env';path.write_text('EXISTING_SETTING=retained\n')
    result=save_verified_settings('sender@gmail.com','admin@example.com','abcd efgh ijkl mnop',env_path=path,smtp_factory=factory)
    factory.assert_called_once_with('smtp.gmail.com',587,timeout=15);smtp.starttls.assert_called_once();smtp.login.assert_called_once_with('sender@gmail.com','abcdefghijklmnop')
    smtp.send_message.assert_not_called();smtp.sendmail.assert_not_called()
    values=dotenv_values(path);assert values['SMTP_FROM']=='ExtSecure <sender@gmail.com>' and values['ADMIN_EMAILS']=='admin@example.com'
    assert values['EXISTING_SETTING']=='retained' and result['email_sent'] is False


def test_rejected_gmail_credentials_are_not_saved(tmp_path):
    factory=MagicMock();factory.return_value.__enter__.return_value.login.side_effect=smtplib.SMTPAuthenticationError(535,b'fixture')
    path=tmp_path/'.env';path.write_text('EXISTING_SETTING=retained\n')
    with pytest.raises(smtplib.SMTPAuthenticationError):save_verified_settings('sender@gmail.com','admin@example.com','abcdefghijklmnop',env_path=path,smtp_factory=factory)
    assert path.read_text()=='EXISTING_SETTING=retained\n'


@pytest.mark.parametrize('change',[{'sender':'not-an-email'},{'recipient':'admin@example.com\r\nBcc: other@example.com'},{'password':'short'},{'display_name':'ExtSecure\nBcc: other@example.com'}])
def test_invalid_setup_never_contacts_smtp_or_writes(tmp_path,change):
    data={'sender':'sender@gmail.com','recipient':'admin@example.com','password':'abcdefghijklmnop',**change}
    factory=MagicMock();path=tmp_path/'.env'
    with pytest.raises(ValueError):save_verified_settings(**data,env_path=path,smtp_factory=factory)
    factory.assert_not_called();assert not path.exists()
