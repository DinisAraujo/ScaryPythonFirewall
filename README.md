# Scary Python Firewall

Basically it blocks an IP when it sends a **determined amount of SYN packets** in a determined amount of time.This usually happens when someone runs a SYN scan using an enumeration tool like Nmap

However, before blocking it sends a SYN-ACK to establish a connection with the attacker and then sends a custom message through that TCP channel.

You can read my **Medium post** about it here:
- https://medium.com/@dinis.araujo.costa/building-a-firewall-that-scares-hackers-351b074cab48

**Note**:
  - You must **run it as sudo** because it uses the port numbers scanned by the attacker to respond (usually < 1024)
