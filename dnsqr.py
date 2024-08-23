#!/home/kuro/Repositio/resolvi/.venv/bin/python3

from scapy.all import DNS, DNSQR, Ether, IP, srploop, UDP

dns_req = Ether(src='58:47:ca:74:6b:c4', dst='58:47:ca:74:6b:c3')/IP(dst='169.254.0.2', src='169.254.0.1')/UDP(dport=53,sport=12345)/DNS(rd=1, qd=DNSQR(qname='www.bilibili.com'))
answer = srploop(dns_req, verbose=0, iface='enp2s0f1')

print(answer[DNS].summary())
