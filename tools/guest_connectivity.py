"""Probe only fixed lab/management addresses, never unrelated third-party systems."""
import json
import socket

targets = [('10.77.0.20',25,True), ('10.77.0.20',53,True),
           ('10.77.0.20',1025,False), ('10.77.0.20',8025,False),
           ('192.168.56.1',25,False), ('192.168.56.51',22,False)]
results = []
for address, port, expected in targets:
    with socket.socket() as sock:
        sock.settimeout(2)
        try:
            connected = sock.connect_ex((address,port)) == 0
        except OSError:
            connected = False
    results.append(dict(address=address,port=port,expected=expected,connected=connected))
print(json.dumps(results,indent=2))
raise SystemExit(0 if all(r['expected'] == r['connected'] for r in results) else 2)
