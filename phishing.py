import re
import requests
import validators
import time

# --- API Keys (replace with your real keys) ---
VIRUSTOTAL_API_KEY = 'a5f278306edb15871ca1f3ab4626d22ff18f4de4dc04354ccb934af355f2152d'
URLSCAN_API_KEY = '01970ca1-531b-7629-a8db-02a5d9cef882'

# --- Heuristic Checks ---
def is_suspicious_url(url):
    heuristics = [
        lambda u: len(u) > 75,
        lambda u: re.search(r'@\w+', u),
        lambda u: u.count('.') > 5,
        lambda u: re.search(r'https?://\d+\.\d+\.\d+\.\d+', u),
        lambda u: re.search(r'(login|verify|update|secure|account)', u.lower()),
        lambda u: re.search(r'-', u.split("//")[-1]),
    ]
    return any(check(url) for check in heuristics)

# --- VirusTotal API Check ---
def check_with_virustotal(url):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    params = {"url": url}
    vt_url = "https://www.virustotal.com/api/v3/urls"

    try:
        response = requests.post(vt_url, headers=headers, data=params)
        if response.status_code != 200:
            print(f"[!] VirusTotal error: {response.status_code}, {response.text}")
            return "Error querying VirusTotal"

        url_id = response.json()['data']['id']
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
        time.sleep(5)
        analysis_response = requests.get(analysis_url, headers=headers)

        if analysis_response.status_code != 200:
            print(f"[!] VirusTotal analysis error: {analysis_response.status_code}, {analysis_response.text}")
            return "Error fetching analysis"

        stats = analysis_response.json()['data']['attributes']['stats']
        return "Malicious" if stats['malicious'] > 0 or stats['suspicious'] > 0 else "Clean"
    except Exception as e:
        print(f"[!] Exception in VirusTotal check: {e}")
        return "Error querying VirusTotal"

# --- urlscan.io API Check ---
def check_with_urlscan(url):
    headers = {
        'API-Key': URLSCAN_API_KEY,
        'Content-Type': 'application/json'
    }
    data = {
        "url": url,
        "visibility": "unlisted"  # Less likely to trigger spam prevention
    }

    try:
        response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data)
        if response.status_code != 200:
            json_err = response.json()
            if "description" in json_err:
                print(f"[!] urlscan.io blocked the scan: {json_err['description']}")
                return "Blocked by urlscan.io"
            else:
                print(f"[!] urlscan.io error: {response.status_code}, {response.text}")
                return "Error submitting to urlscan.io"

        result_url = response.json().get('api')
        print("[*] Submitted to urlscan.io. Waiting for result...")
        time.sleep(10)
        result_response = requests.get(result_url)

        if result_response.status_code != 200:
            print(f"[!] Error retrieving result: {result_response.status_code}, {result_response.text}")
            return "Error retrieving urlscan.io result"

        result_data = result_response.json()
        verdict = result_data.get('verdicts', {}).get('overall', {}).get('score', 0)

        return "Suspicious" if verdict > 0 else "Clean"
    except Exception as e:
        print(f"[!] Exception in urlscan.io check: {e}")
        return "Error submitting to urlscan.io"

# --- Main Scanner Function ---
def scan_url(url):
    if not validators.url(url):
        return "Invalid URL format"

    print("[*] Running heuristic checks...")
    heuristics_result = "Suspicious" if is_suspicious_url(url) else "Clean"
    if heuristics_result == "Suspicious":
        print("[!] URL flagged as suspicious by heuristics")

    print("[*] Checking with VirusTotal...")
    vt_result = check_with_virustotal(url)
    print(f"[+] VirusTotal Result: {vt_result}")

    print("[*] Checking with urlscan.io...")
    us_result = check_with_urlscan(url)
    print(f"[+] urlscan.io Result: {us_result}")

    return (
        "\n===== Scan Summary =====\n"
        f"- Heuristics: {heuristics_result}\n"
        f"- VirusTotal: {vt_result}\n"
        f"- urlscan.io: {us_result}\n"
    )

# --- Entry Point ---
if __name__ == "__main__":
    user_url = input("Enter a URL to scan: ").strip()
    result = scan_url(user_url)
    print(result)
