"""Generates the ARC test vector with dkimpy, an implementation independent
from ours: a mail signed by example.com, then sealed by two intermediaries
(a mailing list that changes the subject, then a forwarding service).

    PYTHONPATH=<dkimpy> python3 gen_arc.py key.pem

Uses the key of dkim-key.txt (selector test, domain example.com) for every
signature. Writes arc-chain.eml.
"""
import sys

import dkim

key = open(sys.argv[1], "rb").read()
message = (
    b"From: Joe SixPack <joe@example.com>\r\n"
    b"To: list@lists.example.com\r\n"
    b"Subject: Is dinner ready?\r\n"
    b"Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n"
    b"Message-ID: <20030712040037.46341.5F8J@example.com>\r\n"
    b"\r\n"
    b"Hi.\r\n"
)
message = dkim.sign(message, b"test", b"example.com", key, include_headers=[b"from", b"to", b"subject", b"date"]) + message

# The list checks the mail, then changes the subject: DKIM breaks.
message = b"Authentication-Results: lists.example.com; dkim=pass header.d=example.com; spf=pass smtp.mailfrom=example.com\r\n" + message
for header in dkim.arc_sign(message, b"test", b"example.com", key, b"lists.example.com", timestamp=1790940692):
    message = header + message
message = message.replace(b"Subject: Is dinner ready?", b"Subject: [list] Is dinner ready?")

# The forwarding service sees DKIM failing, but a valid chain.
message = b"Authentication-Results: forward.example.com; dkim=fail header.d=example.com; arc=pass\r\n" + message
for header in dkim.arc_sign(message, b"test", b"example.com", key, b"forward.example.com", timestamp=1790940700):
    message = header + message
open("arc-chain.eml", "wb").write(message)
