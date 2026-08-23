#!/usr/bin/env python3
import paramiko
import time
import sys

R1_IP = "192.168.100.1"
R1_PORT = 830
R1_USER = "admin"
R1_PASS = "Cisco123"

HELLO = b'<?xml version="1.0" encoding="UTF-8"?><hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>]]>]]>'

GET_ACL_RPC = b'''<?xml version="1.0" encoding="UTF-8"?>
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
  <get-config>
    <source><running/></source>
    <filter type="subtree">
      <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
        <ip>
          <access-list/>
        </ip>
      </native>
    </filter>
  </get-config>
</rpc>]]>]]>'''

def recv_until(chan, marker=b']]>]]>', timeout=10):
    buf = b''
    chan.settimeout(timeout)
    try:
        while marker not in buf:
            buf += chan.recv(4096)
    except Exception:
        pass
    return buf

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(R1_IP, port=R1_PORT, username=R1_USER, password=R1_PASS,
               look_for_keys=False, allow_agent=False)
chan = client.get_transport().open_session()
chan.invoke_subsystem('netconf')

hello = recv_until(chan)
print("[+] Server hello received, length:", len(hello))

chan.sendall(HELLO)
time.sleep(0.5)
chan.sendall(GET_ACL_RPC)

reply = recv_until(chan)
print(reply.decode(errors='replace'))

chan.close()
client.close()
