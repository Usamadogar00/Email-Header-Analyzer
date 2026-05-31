import email
import sys
import re

def analyze_email_headers(file_path):
    print(f"[*] Analyzing email headers from: {file_path}\n")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            msg = email.message_from_file(f)
            
        print("--- Basic Information ---")
        print(f"From: {msg.get('From')}")
        print(f"To: {msg.get('To')}")
        print(f"Subject: {msg.get('Subject')}")
        print(f"Date: {msg.get('Date')}\n")
        
        print("--- Security Checks ---")
        
        # Check SPF, DKIM, DMARC Results usually found in Authentication-Results
        auth_results = msg.get('Authentication-Results')
        if auth_results:
            print("[+] Authentication Results Found:")
            if 'spf=pass' in auth_results.lower():
                print("    - SPF: Pass")
            else:
                print("    - SPF: Fail / Not Found (Suspicious)")
                
            if 'dkim=pass' in auth_results.lower():
                print("    - DKIM: Pass")
            else:
                print("    - DKIM: Fail / Not Found (Suspicious)")
        else:
            print("[-] No Authentication-Results header found. This email might be spoofed!\n")

        # Extract Received IPs to trace the origin
        print("\n--- Hop Trace (Received Headers) ---")
        received_headers = msg.get_all('Received')
        if received_headers:
            ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
            for i, header in enumerate(received_headers):
                ips = ip_pattern.findall(header)
                if ips:
                    print(f"Hop {i+1}: Found IPs -> {', '.join(set(ips))}")
        else:
            print("[-] No Received headers found.")

    except FileNotFoundError:
        print("[-] Error: EML file not found.")
    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <path_to_email.eml>")
    else:
        analyze_email_headers(sys.argv[1])
