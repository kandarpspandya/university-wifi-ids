import requests
import time
import json
import socket
import subprocess  # Use subprocess for better control
from database import store_scan_result

# Replace with your actual VirusTotal API key (KEEP IT SECRET!)
VIRUSTOTAL_API_KEY = "d90783f2fc5800160ffcd218055749bf731a22da3c0f6109a07e1cda6f88fc3b"

def scan_file(file_content, filename, api_key=VIRUSTOTAL_API_KEY):
    try:
        files = {"file": (filename, file_content)}
        response = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers={"x-apikey": api_key},
            files=files,
        )
        response.raise_for_status()
        analysis_id = response.json()["data"]["id"]

        while True:
            response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers={"x-apikey": api_key},
            )
            response.raise_for_status()
            analysis_data = response.json()["data"]
            if analysis_data["attributes"]["status"] == "completed":
                break
            time.sleep(5)

        results = analysis_data["attributes"]["results"]
        for engine, result in results.items():
            if result["category"] == "malicious":
                result_data = {"virus": True, "message": f"Malicious: {engine}"}
                store_scan_result(filename, json.dumps(result_data))
                return result_data

        result_data = {"virus": False, "message": "No threats found."}
        store_scan_result(filename, json.dumps(result_data))
        return result_data

    except requests.exceptions.RequestException as e:
        result_data = {"error": True, "message": f"Error during scanning: {e}"}
        store_scan_result(filename, json.dumps(result_data))
        return result_data
    except Exception as e:
        result_data = {"error": True, "message": f"Unexpected error: {e}"}
        store_scan_result(filename, json.dumps(result_data))
        return result_data

def analyze_traffic(traffic_data):
    # Place holder function. You should implement your traffic analysis here.
    # For now, it just prints the traffic data.
    print(f"Analyzing traffic: {traffic_data}")
    return {"analysis": "Traffic analysis placeholder"}

def deep_scan(target):
    """
    Performs a deep scan on the target IP address or domain name and returns a
    user-friendly security assessment.
    """
    try:
        ip_address = socket.gethostbyname(target)
        nmap_command = ["nmap", "-p", "1-1000", ip_address]
        print(f"Executing nmap command: {nmap_command}")
        result = subprocess.run(nmap_command, capture_output=True, text=True)

        if result.returncode != 0:
            return {
                "safe": False,
                "summary": "Network scan failed.",
                "details": f"nmap returned an error: {result.stderr}",
                "remediation": "Check the target and your network connection."
            }

        nmap_output = result.stdout
        print(f"Nmap Output: {nmap_output}") # Print Nmap output

        # Parse nmap output (this is the complex part, you'll need to adapt this)
        open_ports = []
        for line in nmap_output.splitlines():
            if "open" in line:
                parts = line.split()
                port = parts[0].split("/")[0]
                service = parts[2]
                open_ports.append({"port": port, "service": service})

        if not open_ports:
            return {
                "safe": True,
                "summary": "No open ports found.  The target appears to be secure.",
                "details": "No services are exposed.",
                "remediation": "Ensure that the system is configured to minimize exposed services."
            }

        #  Security Assessment and Remediation (customize this)
        vulnerabilities = []
        remediation_steps = []
        for port_data in open_ports:
            port = port_data["port"]
            service = port_data["service"]
            if port == "22":
                vulnerabilities.append("SSH service is running.  SSH can be vulnerable to brute-force attacks.")
                remediation_steps.append(
                    "Ensure SSH uses strong passwords or, ideally, key-based authentication.  Disable password authentication if possible. Keep SSH up to date."
                )
            elif port == "80" or port == "443":
                vulnerabilities.append(f"HTTP/HTTPS service is running on port {port}. Web servers can have vulnerabilities.")
                remediation_steps.append(
                    "Keep the web server software and any web applications up to date.  Use HTTPS (port 443) to encrypt traffic.  Configure firewalls and intrusion detection systems."
                )
            # Add more port/service checks here
            else:
                vulnerabilities.append(f"Port {port} is open.")
                remediation_steps.append("Investigate the service running on this port and ensure it is secure.  Close the port if it is not needed.")

        if vulnerabilities:
            return {
                "safe": False,
                "summary": "Potentially vulnerable services detected.",
                "details": "\n".join(vulnerabilities),
                "remediation": "\n".join(remediation_steps)
            }
        else:
            return {
                "safe": True,
                "summary": "Open ports found, but no known high-risk vulnerabilities detected.",
                "details": "The following ports are open:" +  "\n".join([f"{p['port']}: {p['service']}" for p in open_ports]),
                "remediation": "Ensure all services are up to date and securely configured."
            }


    except socket.gaierror:
        return {
            "safe": True,  # Consider this safe, or you might want a different category
            "summary": f"Could not resolve domain name: {target}",
            "details": f"The target domain name could not be resolved to an IP address.",
            "remediation": "Check the domain name and your DNS settings."
        }
    except subprocess.CalledProcessError as e:
        return {
            "safe": False,
            "summary": "Error running nmap.",
            "details": f"nmap exited with code {e.returncode}.  Output:\n{e.stderr}",
            "remediation": "Make sure nmap is installed correctly and is in your system's PATH."
        }
    except Exception as e:
        return {
            "safe": False,
            "summary": "Unexpected error during deep scan.",
            "details": f"Error: {e}",
            "remediation": "Check the server logs for more information."
        }