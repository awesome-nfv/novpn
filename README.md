# NoVPN
A reengineering over Google's Beyond Corp.

- [ ] Route any IP packet through the gateway.
- [ ] Send digitally signed binary files to be executed on the client.
- [ ] Authenticate client claims on the gateways.


Encapsulation:

Client -> Gateway

Encrypted Message
---------------------------
UserID (4 Bytes)
DestinationIP (4 Bytes)
Variable Message + Padding
---------------------------
UDP (Random Port -> 444)
IP (IP Client -> IP Gateway)