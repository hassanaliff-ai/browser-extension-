"""Build a device installation ZIP; never distribute API or certificate secrets."""
from pathlib import Path
import argparse,ipaddress,json,re,zipfile

def build(root,host,port,public_certificate,output):
    host=str(ipaddress.IPv4Address(host));origin=f'https://{host}:{port}'
    if not ipaddress.ip_address(host).is_private:raise ValueError('Use a private LAN address')
    with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as package:
        for file in sorted((root/'extension').rglob('*')):
            relative=file.relative_to(root/'extension')
            if not file.is_file() or any(part in {'tests','node_modules','_metadata','__pycache__'} or part.startswith('.') for part in relative.parts):continue
            data=file.read_bytes()
            if relative.as_posix()=='core.js':
                data=re.sub(r"export const API_ORIGIN = '[^']+';",f"export const API_ORIGIN = '{origin}';",data.decode()).encode()
            elif relative.as_posix()=='manifest.json':
                manifest=json.loads(data);manifest['content_security_policy']['extension_pages']=re.sub(r'connect-src [^;]+;',f'connect-src {origin};',manifest['content_security_policy']['extension_pages']);data=json.dumps(manifest,indent=2).encode()
            elif relative.as_posix()=='rules/navigation.json':
                rules=json.loads(data);rules.append({'id':3,'priority':200,'action':{'type':'allow'},'condition':{'regexFilter':'^'+re.escape(origin)+'/','resourceTypes':['main_frame'],'isUrlFilterCaseSensitive':True}});data=json.dumps(rules).encode()
            elif relative.as_posix()=='workspace-kit.js':data=data.replace(b'http://127.0.0.1:8001',origin.encode())
            package.writestr(relative.as_posix(),data)
        package.write(public_certificate,'ExtSecure API Trust Certificate.cer')
        package.writestr('INSTALL ON ANOTHER DEVICE.txt',f'''ExtSecure same-network installation
API: {origin}
1. Extract this ZIP into a permanent folder.
2. Double-click ExtSecure API Trust Certificate.cer. Install Certificate -> Current User -> Place all certificates in the following store -> Trusted Root Certification Authorities. Verify this certificate came from Hasan before trusting it. The ZIP contains only the public certificate, never its private key.
3. Restart Chrome if it was already open. Visit {origin}/health. It must show SecureScope API with no certificate error.
4. Open chrome://extensions, enable Developer mode, click Load unpacked and select this folder.
5. Register/sign in with your own account and complete administrator account approval. Open My account, choose device access and Add this device. Complete device approval where required.
6. Click Connect Chrome extensions and grant the optional management permission.
The host laptop must be on, its API and HTTPS gateway running, and both computers must reach each other on the same network. Guest Wi-Fi may isolate devices. Never share Hasan's main administrator credentials. If the host IP changes, rebuild and resend this ZIP. Do not bypass certificate warnings.
''')
    return origin

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--host',required=True);parser.add_argument('--port',type=int,default=8766);parser.add_argument('--certificate',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    print(build(Path(__file__).resolve().parents[1],args.host,args.port,args.certificate,args.output))
