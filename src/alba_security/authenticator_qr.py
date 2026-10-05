"""Generate authenticator enrollment images locally, without caching secrets."""
from __future__ import annotations

from io import BytesIO
import re

import pyotp
import qrcode


def authenticator_qr_png(uri: str, *, secret: str | None = None) -> bytes:
    """Encode a validated ExtSecure TOTP URI as a standard black/white QR PNG."""
    try:
        if not isinstance(uri, str) or len(uri) > 2048:
            raise ValueError
        authenticator = pyotp.parse_uri(uri)
        if (
            not isinstance(authenticator, pyotp.TOTP)
            or authenticator.issuer != 'ExtSecure'
            or authenticator.digits != 6
            or authenticator.interval != 30
            or not authenticator.name
            or not re.fullmatch(r'[A-Z2-7]{32,}', authenticator.secret)
            or (secret is not None and authenticator.secret != secret)
        ):
            raise ValueError
        authenticator.at(0)  # Reject malformed base32 before showing an image.
    except (ValueError, TypeError, AttributeError):
        # Never include the URI or secret in an error shown to the user/logs.
        raise ValueError('Authenticator setup details are invalid. Restart enrollment.') from None

    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=4)
    qr.add_data(uri, optimize=0)
    qr.make(fit=True)
    image = qr.make_image(fill_color='black', back_color='white')
    output = BytesIO()
    image.save(output, format='PNG')
    return output.getvalue()
