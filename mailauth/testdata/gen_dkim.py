"""Generates the DKIM test vectors with dkimpy, an implementation independent
from ours, so that a canonicalization bug cannot cancel itself out.

    openssl genrsa -out key.pem 2048
    PYTHONPATH=<dkimpy> python3 gen_dkim.py key.pem

Writes dkim-*.eml and dkim-key.txt (the DNS TXT record of test._domainkey.example.com).
"""
import base64
import subprocess
import sys

import dkim

key = open(sys.argv[1], "rb").read()
der = subprocess.run(["openssl", "rsa", "-in", sys.argv[1], "-pubout", "-outform", "DER"],
                     capture_output=True, check=True).stdout
open("dkim-key.txt", "w").write("v=DKIM1; k=rsa; p=" + base64.b64encode(der).decode() + "\n")

message = (
    b"From: Joe SixPack <joe@example.com>\r\n"
    b"To: Suzie Q <suzie@shopping.example.net>\r\n"
    b"Subject:   Is dinner\t ready?  \r\n"
    b"  folded continuation\r\n"
    b"Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n"
    b"Message-ID: <20030712040037.46341.5F8J@example.com>\r\n"
    b"\r\n"
    b"Hi.  \r\n"
    b"\r\n"
    b"We lost the game.\t Are you hungry yet?\r\n"
    b"\r\n"
    b"Joe.\r\n"
    b"\r\n"
    b"\r\n"
)
headers = [b"from", b"to", b"subject", b"date", b"message-id", b"from", b"reply-to"]

for header, body in [(b"relaxed", b"relaxed"), (b"simple", b"simple"), (b"relaxed", b"simple"), (b"simple", b"relaxed")]:
    signature = dkim.sign(message, b"test", b"example.com", key, canonicalize=(header, body),
                          include_headers=headers)
    name = "dkim-%s-%s.eml" % (header.decode(), body.decode())
    open(name, "wb").write(signature + message)

signature = dkim.sign(message, b"test", b"example.com", key, include_headers=headers, length=True,
                      canonicalize=(b"relaxed", b"relaxed"))
open("dkim-length.eml", "wb").write(signature + message)
