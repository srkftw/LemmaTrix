"""Continuous unrelated UART output cannot indefinitely extend a request."""
import socket, sys, tempfile, threading, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import live

def main():
    with tempfile.TemporaryDirectory(prefix='lt-portal-deadline-') as directory:
        path=Path(directory)/'portal.sock'
        listener=socket.socket(socket.AF_UNIX);listener.bind(str(path));listener.listen(1)
        def output():
            connection,_=listener.accept()
            with connection:
                connection.recv(1024)
                for _ in range(40):
                    try:connection.sendall(b'unrelated-event\n')
                    except (BrokenPipeError,ConnectionResetError):break
                    time.sleep(.02)
        sender=threading.Thread(target=output,daemon=True);sender.start()
        client=live.Client(path,timeout=.15);started=time.monotonic()
        try:
            try:client.request(2)
            except TimeoutError:pass
            else:raise AssertionError('unrelated stream output completed a request')
            elapsed=time.monotonic()-started
            assert .10<=elapsed<.5,('absolute deadline not enforced',elapsed)
            assert len(client.buffer)<4096
            print('PASS absolute request deadline under continuous unrelated bytes',round(elapsed,3))
        finally:client.close();listener.close();sender.join(timeout=1)

if __name__=='__main__':main()
