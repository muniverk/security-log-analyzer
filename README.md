# Security Log Analyzer

**Author:** Muniver Kharod  
**Project Type:** Python cybersecurity project  
**Focus:** Security monitoring, suspicious login detection, and simple alert reporting  

## Project Summary
This project analyzes authentication logs and flags suspicious activity such as:
- repeated failed login attempts
- successful access after multiple failures
- possible impossible-travel events

It is a beginner-friendly project that demonstrates Python programming, security monitoring logic, and structured reporting through CSV and JSON files.

## Why this project is relevant
This project shows experience with:
- Python
- cybersecurity fundamentals
- threat detection logic
- log analysis
- incident identification
- alert reporting

## Files included
- `security_log_analyzer.py` → main Python script
- `sample_auth.log` → sample log file to test the project
- `alerts.csv` → generated alert report
- `summary.json` → generated summary report
- `sample_run_output.txt` → example terminal output
- `README.md` → project instructions

## How to run it on your computer

### Step 1: Make sure Python is installed
Open Terminal and type:

```bash
python3 --version
```

If Python is installed, you should see a version number.

### Step 2: Put the project folder somewhere easy to find
For example:
- Downloads
- Desktop

If you downloaded the zip file, unzip it first.

### Step 3: Open Terminal
On Mac:
- press `Command + Space`
- type `Terminal`
- press Enter

### Step 4: Go into the project folder
If the folder is in Downloads, type:

```bash
cd ~/Downloads/security_log_analyzer
```

If it is somewhere else, go to that folder instead.

### Step 5: Run the script
Type:

```bash
python3 security_log_analyzer.py --input sample_auth.log
```

### Step 6: View the generated files
After running it, these files will be created or updated in the same folder:
- `alerts.csv`
- `summary.json`

You can open them normally:
- `alerts.csv` in Excel, Numbers, or Google Sheets
- `summary.json` in VS Code or any text editor

## Important note
This project does **not** need to be compiled.

Python is an interpreted language, so you **run** it instead of compiling it.

## Example output
When you run the script with the sample log file, it will produce alerts such as:
- repeated failed logins from the same IP
- impossible travel between countries in a short time

