Now step-by-step — What exactly happens when you run it?


Step	What Happens
1	You run python gui.py → The GUI window appears.
2	You click Start Firewall button.
3	Behind the scenes, it uses Scapy to start sniffing (reading) network packets that are coming in/out of your machine.
4	For every packet, it:
→ Checks Source IP, Destination IP, Source Port, Destination Port, and Protocol.
→ Compares them against the rules in rules.json
5	Based on the rule matched:
→ If allow, it logs to allowed.log
→ If block, it logs to blocked.log
→ If suspicious attack (e.g., flooding), it logs to attacks.log
6	You can click View Logs in the GUI to open and read the logs anytime.
7	If you change rules.json, you click Reload Rules button — no need to restart program.
8	When done, you click Stop Firewall. It stops sniffing packets.
9	During demonstration/viva, you can show the allowed/blocked packets and attack detection.
🔍 Practical Example (Real Simulation)
Suppose your rules.json says:

Block all packets from IP 192.168.1.100

Allow all traffic going to port 443 (HTTPS)

Now:

If you try to ping 192.168.1.100, or if that machine tries to send you packets →
❌ Blocked → Entry made in blocked.log

If you browse https://www.google.com (port 443) →
✅ Allowed → Entry made in allowed.log

If a hacker tries to flood you with 100 packets in 1 second →
🚨 Attack detected → Entry made in attacks.log

🛡️ Where exactly the Firewall is running?
Inside your Python program, capturing and analyzing packets.

It does not modify the operating system's real firewall (like Windows Defender or Linux iptables).

It’s a "user-space firewall" simulation — perfect for learning and demonstrating security concepts safely.

✅ No risk to your real network.
✅ But real packets are being monitored.