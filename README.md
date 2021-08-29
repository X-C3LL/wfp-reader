# WFP Reader

This is just a simple proof of concept where I use Windows Filter Platform as a covert channel for incoming communications. The main idea is explained in my article [Knock! Knock! The postman is here! (abusing Mailslots and PortKnocking for connectionless shells)](https://adepts.of0x.cc/connectionless-shells/), and it can be summarized as using source ports to carry the encoded messages. We use WFP to get the information from the events, so we can hit a well-known port (UDP 123, for example) and vary the source port to encode 2 bytes of information per request.


On the other hand, if you are interested on playing with Port Knocking in Windows the code can be helpful to you.
# Usage
To use the WFP APIs you need to run the executable as a privileged user (administrator). Run the wfp-reader.exe in your VM and then in other VM execute this small snippet:

```python
import sys
from scapy.all import *


def textToPorts(text):
 chunks = [text[i:i+2] for i in range(0, len(text), 2)]
 for chunk in chunks:
     send(IP(dst=sys.argv[1])/UDP(dport=123,sport=int("0x" + chunk[::-1].encode("hex"), 16))/Raw(load="Use stealthier packet in a real operation, pls"))

if __name__ == "__main__":
 while 1:
     command = raw_input("Insert text> ")
     textToPorts(command)
```

This python will encode your text inside the source port of UDP packets sent to the remote server at port 123.

```
➜  working sudo python messenger.py 10.0.2.7
Insert text> Hello World!
.
Sent 1 packets.
.
Sent 1 packets.
.
Sent 1 packets.
.
Sent 1 packets.
.
Sent 1 packets.
.
Sent 1 packets.
```

And at wfp-reader.exe you are going to see the messages:

```
C:\Users\avispa.marina\Source\Repos\wfp-reader\wfp-reader\bin\Debug\netcoreapp3.1>wfp-reader.exe
        -=[Proof of concept - Covert Channel using Windows Filtering Platform]=-


Hello World!
```

# Author
Juan Manuel Fernandez ([@TheXC3LL](https://twitter.com/TheXC3LL))
