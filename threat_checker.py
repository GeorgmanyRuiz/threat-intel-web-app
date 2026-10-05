import sys
import requests
import json

# Replace with your actual AbuseIPDB API key
API_KEY = "1cb3bc16659bdf5f7910fd1558f86d3d0d6ef47b44f4a86c5d3f9bc86e2c8df5cb03d3643adbe8ac"

def check_ip_reputation(ip_address):
    url = "https://api.abuseipdb.com/api/v2/check"
    
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }
    
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }

    print(f"\n[*] Querying AbuseIPDB Threat Intel API for IP: {ip_address}...\n")
    
    try:
        response = requests.get(url, headers=headers, params=params)
        
        if response.status_code == 200:
            data = response.json()['data']
            
            print("=" * 45)
            print(f" THREAT INTELLIGENCE REPORT: {data.get('ipAddress')}")
            print("=" * 45)
            print(f" Abuse Confidence Score : {data.get('abuseConfidenceScore')}%")
            print(f" ISP                     : {data.get('isp')}")
            print(f" Domain                  : {data.get('domain')}")
            print(f" Country                 : {data.get('countryCode')}")
            print(f" Total Reports          : {data.get('totalReports')}")
            print(f" Usage Type              : {data.get('usageType')}")
            print("=" * 45)
            
            # Risk Verdict Logic
            score = data.get('abuseConfidenceScore', 0)
            if score > 50:
                print(" [VERDICT] HIGH RISK IP - Recommend Firewall Block.")
            elif score > 15:
                print(" [VERDICT] MEDIUM RISK - Monitor Traffic.")
            else:
                print(" [VERDICT] LOW RISK / CLEAN IP.")
            print("=" * 45 + "\n")
            
        else:
            print(f"[-] API Error {response.status_code}: {response.text}")
            
    except Exception as e:
        print(f"[-] Connection failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 threat_checker.py <IP_ADDRESS>")
        sys.argv.append("118.25.6.39")  # Default test malicious IP
        
    target = sys.argv[1]
    check_ip_reputation(target)
