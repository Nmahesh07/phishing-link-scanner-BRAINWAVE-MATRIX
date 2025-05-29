import re
import requests
import validators
import time
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# Replace this with your real VirusTotal API Key
VIRUSTOTAL_API_KEY = "a5f278306edb15871ca1f3ab4626d22ff18f4de4dc04354ccb934af355f2152d"

# -----------------------
# Detection Logic
# -----------------------

def is_suspicious_url(url):
    checks = [
        lambda u: len(u) > 75,
        lambda u: '@' in u,
        lambda u: u.count('.') > 5,
        lambda u: re.search(r'https?://\d+\.\d+\.\d+\.\d+', u),
        lambda u: any(word in u.lower() for word in ['login', 'verify', 'update', 'secure', 'account', 'bank']),
        lambda u: '-' in u.split("//")[-1].split('/')[0],
    ]
    return any(check(url) for check in checks)

def scan_with_virustotal(url):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url}
    try:
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
        if response.status_code != 200:
            return "VirusTotal submission failed"

        url_id = response.json()['data']['id']
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"

        for _ in range(10):
            result = requests.get(analysis_url, headers=headers)
            if result.status_code == 200:
                status = result.json()['data']['attributes']['status']
                if status == "completed":
                    stats = result.json()['data']['attributes']['stats']
                    if stats['malicious'] > 0 or stats['suspicious'] > 0:
                        return "Malicious (VirusTotal)"
                    else:
                        return "Clean (VirusTotal)"
            time.sleep(2)
        return "Timeout or unknown result"
    except Exception as e:
        return f"Error: {e}"

# -----------------------
# GUI Actions
# -----------------------

def scan_url():
    url = url_entry.get().strip()
    output_box.delete('1.0', tk.END)
    status_var.set("Scanning...")

    if not validators.url(url):
        messagebox.showerror("Invalid URL", "Please enter a valid URL.")
        status_var.set("Invalid URL")
        return

    output_box.insert(tk.END, f"🔍 Scanning URL: {url}\n\n")

    # Heuristics
    if is_suspicious_url(url):
        output_box.insert(tk.END, "⚠️ Heuristic: Suspicious patterns found.\n")
    else:
        output_box.insert(tk.END, "✅ Heuristic: No suspicious patterns.\n")

    # VirusTotal
    output_box.insert(tk.END, "\n⏳ Checking VirusTotal...\n")
    vt_result = scan_with_virustotal(url)
    output_box.insert(tk.END, f"🔎 VirusTotal Result: {vt_result}\n")

    # Final verdict
    if "Malicious" in vt_result or is_suspicious_url(url):
        output_box.insert(tk.END, "\n❗ Final Verdict: Possibly Phishing/Malicious", "danger")
        status_var.set("Result: ⚠️ Phishing/Malicious")
    else:
        output_box.insert(tk.END, "\n✔️ Final Verdict: Safe", "safe")
        status_var.set("Result: ✅ Safe")

def clear_all():
    url_entry.delete(0, tk.END)
    output_box.delete('1.0', tk.END)
    status_var.set("Ready")

# -----------------------
# GUI Setup
# -----------------------

app = tk.Tk()
app.title("🔐 Phishing Link Scanner")
app.geometry("750x500")
app.configure(bg="#f4f7fa")
app.resizable(False, False)

# Style Setup
style = ttk.Style(app)
style.theme_use('clam')
style.configure('TButton', font=('Segoe UI', 10), padding=6)
style.configure('TLabel', font=('Segoe UI', 11))
style.configure('TEntry', font=('Segoe UI', 11))

# Header
header = ttk.Label(app, text="🔐 Phishing Link Scanner", font=('Segoe UI', 18, 'bold'), background="#f4f7fa")
header.pack(pady=15)

# URL Entry Frame
url_frame = ttk.Frame(app)
url_frame.pack(pady=5, padx=20, fill='x')
ttk.Label(url_frame, text="Enter URL:").grid(row=0, column=0, sticky='w')
url_entry = ttk.Entry(url_frame, width=70)
url_entry.grid(row=0, column=1, padx=10)
url_entry.focus()

# Buttons
button_frame = ttk.Frame(app)
button_frame.pack(pady=10)
ttk.Button(button_frame, text="🔎 Scan", command=scan_url).pack(side='left', padx=10)
ttk.Button(button_frame, text="🧹 Clear", command=clear_all).pack(side='left', padx=10)

# Output Box
output_box = scrolledtext.ScrolledText(app, height=18, width=85, font=('Courier New', 10))
output_box.pack(padx=20, pady=10)
output_box.tag_config("danger", foreground="red")
output_box.tag_config("safe", foreground="green")

# Status Bar
status_var = tk.StringVar()
status_var.set("Ready")
status_bar = ttk.Label(app, textvariable=status_var, relief='sunken', anchor='w', background="#e6eef2")
status_bar.pack(side='bottom', fill='x')

app.mainloop()
