# QR link checks and misleading filenames

ExtSecure 0.8.17 adds two local checks, available through the toolbar popup and extension console.

## QR link safety check

Open **Monitor → Scan a page**, or **QR check** in the popup. Select a PNG, JPEG or WebP image (up to 8 MiB), then choose **Read QR destination**. A bundled jsQR 1.4.0 decoder reads the image locally. No image is uploaded and no camera permission is required. Crop images around one QR code for reliable results.

The extension displays the normalized destination and hostname for review. It rejects executable/non-web payloads and embedded credentials. Query strings and fragments are removed. Choose **Check QR destination** to use the existing authenticated URL-scanning API. By default only the origin is sent; checking the path requires the explicit checkbox. The destination is never opened automatically. Existing access approvals, risk scoring, alerts, incidents and Critical containment continue to apply to scanned destinations.

## Double-extension warning

In **File checks**, choosing a file such as `invoice.pdf.exe` immediately displays a warning explaining the real final extension. The check recognizes common document/media/archive disguises before executable, script or shortcut extensions. Case, compatibility characters, trailing dots/spaces and text-direction controls are handled. Ordinary names such as `quarterly.final.pdf` are not classified as disguised executables.

After the user submits the existing SHA-256 lookup, the local filename warning remains beside the reputation result, including Low or Unknown results. It is a filename signal, not proof of malware, and it does not overwrite the backend score. Filenames and file contents are not sent to the backend, and the signal is not persisted in scan history. Hash-only checks cannot assess filenames. This feature checks files selected by users; it does not intercept every Chrome download or quarantine operating-system files.

## Dependency

jsQR is packaged locally with its Apache-2.0 license, source attribution and SHA-256 checksum under `extension/vendor`. No remotely hosted script runs in the extension. Project documentation: https://github.com/cozmo/jsQR.

## Verification

The full extension unit suite and isolated real-Chrome checks cover actual PNG QR decoding, unsafe payload rejection, private-parameter removal, explicit path lookup, no automatic navigation or image upload, blank-image errors, immediate filename warnings, warnings surviving a Low reputation result, popup access and JavaScript/CSP errors. Browser checks use labelled synthetic backend responses; they do not claim a live VirusTotal assessment or write test threats to the production database.

Results: **222 unit tests passed; 13 real Chrome checks passed**.
