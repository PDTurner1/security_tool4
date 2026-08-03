
Phish_Scan modifications

Phish_scan2.py – the new python script

Feedback received:
1.	Make the authentication check trust aware.  Rather than believing any Authentication-Results, parse the Received header chain and only honor the results stamped by the final trusted hop.  This will stop an attacker from self-certifying a clean bill of health.
2.	Provide HTML and JSON output options.
3.	Fix readme file to show plain flags.
4.	Reject non-eml files.
5.	Passing off contents of emails to a third party for scanning and validation.
6.	Add an allow list to mute internal senders.

Feedback implemented:
1.	I have made the authentication trust-aware and have included a sample email to test the option.
2.	The tool now has HTML and JSON output options.
3.	Readme file is fixed to show plain flags (-h).
4.	Tool now rejects non-eml files.
Feedback not implemented:
1.	Passing off contents of email to a third party for scanning and validation.  I felt this is an excellent idea and would make the tool more dynamic and updated. I also felt that this would be a completely new tool.
2.	Add an allow list to mute internal senders.  I felt this would partially defeat checking all emails and a spoofed email from an internal sender would go unnoticed.



New command line options for json, html:

python3 phish_scan.py ./emails --json report.json
python3 phish_scan.py ./emails --html report.html
python3 phish_scan.py ./emails --csv report.csv --json report.json --html report.html











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

Initial Claude interaction.txt - My initial Claude AI interaction for the tool.

Phish_scan_Documentation.pdf - pdf of phish_scan documentation.

legit_newsletter.eml - Saved email of a newsletter that passes the phishing test.

phish_scan.py - the phish_scan python file

phishing_paypal.eml - Saved email from "paypal" that fails the phishing test.

phishing_scanner_origial_python file.py - original python file produced by Claude AI.




Thank you.

Patrick
