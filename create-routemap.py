#!/usr/bin/env python3
import paramiko
import time
import sys

R1_IP = "192.168.100.1"
R1_PORT = 830
R1_USER = "admin"
R1_PASS = "Cisco123"

HELLO = b'<?xml version="1.0" encoding="UTF-8"?><hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>]]>]]>'

RPC = b'''<?xml version="1.0" encoding="UTF-8"?>
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
  <edit-config>
    <target><running/></target>
    <config>
      <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
        <route-map>
          <name>PBR_MAP</name>
          <route-map-without-order-seq xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-route-map">
            <seq_no>10</seq_no>
            <operation>permit</operation>
            <match>
              <ip>
                <address>
                  <access-list-ordered>ACL_INTERCEPT</access-list-ordered>
                </address>
              </ip>
            </match>
            <set>
              <ip>
                <next-hop>
                  <address-ordered>192.168.100.2</address-ordered>
                </next-hop>
              </ip>
            </set>
          </route-map-without-order-seq>
        </route-map>
        <route-map>
          <name>TO_GUESTSHELL</name>
          <route-map-without-order-seq xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-route-map">
            <seq_no>10</seq_no>
            <operation>permit</operation>
            <match>
              <ip>
                <address>
                  <access-list-ordered>101</access-list-ordered>
                </address>
              </ip>
            </match>
            <set>
              <ip>
                <next-hop>
                  <address-ordered>192.168.100.2</address-ordered>
                </next-hop>
              </ip>
            </set>
          </route-map-without-order-seq>
        </route-map>
      </native>
    </config>
  </edit-config>
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

try:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(R1_IP, port=R1_PORT, username=R1_USER, password=R1_PASS,
                   look_for_keys=False, allow_agent=False)
    chan = client.get_transport().open_session()
    chan.invoke_subsystem('netconf')

    hello = recv_until(chan)
    print("[+] Server hello length:", len(hello))

    chan.sendall(HELLO)
    time.sleep(0.5)
    chan.sendall(RPC)

    reply = recv_until(chan)
    print("[+] RPC reply:", reply.decode(errors='replace')[:800])

    if b'<ok/>' in reply:
        print("[+] SUCCESS: both route-maps created via NETCONF!")
    else:
        print("[-] Failed")

    chan.close()
    client.close()
except Exception as e:
    print("[-] Error:", e)
    sys.exit(1)
