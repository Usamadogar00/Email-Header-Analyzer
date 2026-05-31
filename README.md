# Email Header Analyzer

A simple, fast Python script designed to parse `.eml` files and analyze their email headers. This tool helps security analysts quickly identify email spoofing and phishing attempts.

## Features
* Extracts basic routing information (From, To, Date, Subject).
* Automatically parses `Authentication-Results` to check the status of **SPF** and **DKIM**.
* Extracts all IP addresses from `Received` headers to help trace the true origin of the email.

## Why I wrote this
During my day-to-day analysis of suspicious emails, manually reading through raw headers looking for SPF failures or hidden origin IPs takes too much time. This script automates the extraction so I can immediately focus on the IOCs.

## Usage
```bash
python analyzer.py suspicious_email.eml
