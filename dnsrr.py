#!/home/kuro/Repositio/resolvi/.venv/bin/python3

from scapy.all import DNS, DNSQR, Ether, IP, srploop, UDP, DNSRR

name = 'www.bilibili.com'

# Crafting the DNS response packet
dns_rsp = Ether(src='58:47:ca:74:6b:c3', dst='58:47:ca:74:6b:c4') / \
          IP(src='169.254.0.2', dst='169.254.0.1') / \
          UDP(sport=53, dport=12345) / \
          DNS(id=1,  # Transaction ID
              qr=1,  # Response
              aa=1,  # Authoritative Answer
              qd=DNSQR(qname=name, qtype='A', qclass='IN'),  # Question Section
              an=DNSRR(rrname=name, type='A', ttl=600, rdata='1.2.3.4'),  # Answer Section
              qdcount=1,  # Number of questions
              ancount=1,  # Number of answers
              nscount=0,  # Number of authority records
              arcount=0)  # Number of additional records

answer = srploop(dns_rsp, verbose=0, iface='virtio_user0')

print(answer[DNS].summary())
