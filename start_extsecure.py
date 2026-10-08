"""Start the configured local AI runtime and ExtSecure API with hidden windows."""
import os
from pathlib import Path
import subprocess
import sys
import time

import httpx
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parent


def reachable(url):
    try:
        with httpx.Client(timeout=2, trust_env=False) as client:
            return client.get(url).is_success
    except httpx.HTTPError:
        return False


def launch(command, environment, log):
    log.parent.mkdir(exist_ok=True)
    with log.open('ab') as output:
        subprocess.Popen(command, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
                         stdout=output, stderr=output,
                         creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)


def wait_until_ready(url):
    for _ in range(30):
        if reachable(url):
            return True
        time.sleep(0.5)
    return False


def main():
    environment = dict(os.environ)
    settings = dotenv_values(ROOT / '.env')
    environment.update({k: v for k, v in settings.items() if v is not None})
    if environment.get('LLM_PROVIDER', 'openai') == 'ollama':
        runtime = Path(os.environ['LOCALAPPDATA']) / 'ExtSecure' / 'ollama'
        environment.update(OLLAMA_HOST='127.0.0.1:11434', OLLAMA_NO_CLOUD='1',
                           OLLAMA_MODELS=str(runtime / 'models'), OLLAMA_NUM_PARALLEL='1',
                           OLLAMA_MAX_LOADED_MODELS='1')
        if not reachable('http://127.0.0.1:11434/api/tags'):
            if not (runtime / 'ollama.exe').is_file():
                print('Local Ollama runtime is missing. Restore it before generating reports.')
                return 1
            launch([str(runtime / 'ollama.exe'), 'serve'], environment, ROOT / '.private' / 'local-ai.log')
            if not wait_until_ready('http://127.0.0.1:11434/api/tags'):
                print('Local AI did not start. Check .private/local-ai.log.')
                return 1
        print('Local AI runtime is running.')
    if not reachable('http://127.0.0.1:8765/health'):
        environment['PYTHONPATH'] = str(ROOT / 'src')
        environment.update(OMP_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1', MKL_NUM_THREADS='1')
        launch([sys.executable, '-m', 'uvicorn', 'main:app', '--host', '127.0.0.1', '--port', '8765'],
               environment, ROOT / '.private' / 'api.log')
        if not wait_until_ready('http://127.0.0.1:8765/health'):
            print('API did not start. Check .private/api.log.')
            return 1
    print('ExtSecure API is running. Open your installed Chrome extension and select Reports.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
