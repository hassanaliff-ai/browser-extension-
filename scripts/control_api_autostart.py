"""Start/stop shortcut entry point using pythonw, without a console window."""
from pathlib import Path
import argparse,subprocess

def main():
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['start','stop']);args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    script=root/'scripts'/f'{args.action}_api_autostart.ps1'
    log=root/'.private/api-supervisor/control.log';log.parent.mkdir(parents=True,exist_ok=True)
    with log.open('ab') as output:
        result=subprocess.run(['powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',str(script)],cwd=root,stdin=subprocess.DEVNULL,stdout=output,stderr=output,creationflags=subprocess.CREATE_NO_WINDOW)
    raise SystemExit(result.returncode)

if __name__=='__main__':main()
