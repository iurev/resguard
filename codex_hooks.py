"""Read actual Codex hook discovery/trust with a bounded app-server session."""
import json
import subprocess
import threading


def list_hooks(cwds):
    proc = subprocess.Popen(['codex', 'app-server', '--stdio'], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    timer = threading.Timer(15, proc.kill)
    timer.daemon = True
    timer.start()
    def request(number, method, params):
        proc.stdin.write(json.dumps({'id': number, 'method': method, 'params': params})+'\n')
        proc.stdin.flush()
        for line in proc.stdout:
            reply = json.loads(line)
            if reply.get('id') == number:
                if 'error' in reply:
                    raise RuntimeError(reply['error'])
                return reply['result']
        raise RuntimeError('Codex hook discovery failed or exceeded 15 seconds')
    try:
        request(1, 'initialize', {'clientInfo': {'name': 'resguard', 'version': '1'},
                                 'capabilities': {'experimentalApi': True}})
        proc.stdin.write('{"method":"initialized"}\n')
        proc.stdin.flush()
        return request(2, 'hooks/list', {'cwds': cwds})['data']
    finally:
        timer.cancel()
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        proc.stdin.close()
        proc.stdout.close()
