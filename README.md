# YARA Rules for Malware Detection

In this project, I have utilized Yara Rules to detect malwares based on their signatures from which can help in detection taking inspiration from [Yara Rules repository](https://github.com/Yara-Rules/rules).

Malware samples have been procured from following repo: [Fabrizio Monaco - Malware Samples](https://github.com/fabrimagic72/malware-samples).

This is an in-development repo. I will be adding more rules for detection of malware.

## Usage

A Python script is created to execute the rules against the sample files. Python script is executable, just need to type below command in the terminal and hit enter:

`./execute_rules.py`

This script can also be used on Windows by creating a batch file.

```
@echo off
REM Change to the directory where the Python script is located`
cd C:\scripts
REM Run the Python script with the full path to the Python executable
C:\Python39\python.exe execute_rules.py
pause
```