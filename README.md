project: Security Log Analyzer  
author: Muniver Kharod  

purpose: This is a small Python project I built to explore basic cybersecurity concepts, specifically how login activity can be analyzed to detect suspicious behavior.

The program reads an authentication log file and looks for patterns that might indicate something unusual. For example, it flags repeated failed login attempts from the same IP address, cases where a user logs in successfully after multiple failures, and situations where a user appears to log in from different countries within a short time period.

The goal of this project was to get more comfortable working with Python while also learning how security monitoring works at a basic level. It also helped me practice organizing output in a way that would be useful for someone reviewing potential security incidents.

What the project uses:
- Python (file handling, loops, conditionals)
- basic pattern detection logic
- simple data reporting using CSV and JSON files

Files in this project:
- security_log_analyzer.py (main script)
- sample_auth.log (test log file)
- alerts.csv (generated alert output)
- summary.json (generated summary data)
- sample_run_output.txt (example of terminal output)

How to run it:

First, make sure Python is installed:

python3 --version

Then open Terminal and navigate to the project folder. For example, if it’s in Downloads:

cd ~/Downloads/security_log_analyzer

Run the script using:

python3 security_log_analyzer.py --input sample_auth.log

After running it, the script will generate:
- alerts.csv
- summary.json

These files contain the detected alerts and a summary of the log activity.

Note:
This project does not require compiling since Python runs directly from the script.

Overall, this project was a way for me to combine programming with basic cybersecurity ideas and get hands-on experience analyzing simple log data.

