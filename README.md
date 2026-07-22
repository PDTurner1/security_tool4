Phish Scan

Phish_scan.py is a python scripted email parser that evaluates emails saved in .eml format for phishing heuristics.  

The problem:

Phishing emails are constant in today’s computing environment.  Both personal and corporate email systems do some checking on incoming emails to try and either flag them or prevent them from being delivered.  

The tool:

My tool is a lightweight tool that can be used to test saved emails for phishing content.  This tool can be used to check emails and as a learning tool to teach others what to look for when reading an email.  I will be using this tool in my monthly security awareness class to demonstrate what to look for when reading a suspicious email.


To run phish_scan:

Python3 phish_scan.py –help (help)

Python3 phish_scan.py saved_email.eml (single email)

Python3 phish_scan.py ./emails (check a folder of emails)

Python3 phish_scan.py saved_email.eml --csv filename (save to .csv file)


Files in this repository:

Initial Claude interaction.txt          My initial Claude AI interaction for the tool.

Phish_scan_Documentation.pdf            pdf of phish_scan documentation.

legit_newsletter.eml                    Saved email of a newsletter that passes the phishing test.

phish_scan.py                           the phish_scan python file

phishing_paypal.eml - Saved email from "paypal" that fails the phishing test.

phishing_scanner_origial_python file.py - original python file produced by Claude AI.


Please email me if you have any issues with the tool.

Thank you.

Patrick
