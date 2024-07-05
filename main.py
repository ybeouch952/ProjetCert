import subprocess
import re
import datetime
import dns.resolver
import requests
import ipaddress
import os

WEBHOOK_URL = "https://ozitem.webhook.office.com/webhookb2/b1271ec2-8fdd-43c5-abc0-be85566dac59@d59105aa-3408-4b50-8581-e3d9fae3b16b/IncomingWebhook/849214c476fb4670be0f4a03050ec588/4f44b746-73a5-43f7-af3a-b71481bf08ab"


clusters = { # Définition des plages d'adresses IP pour chaque cluster
    "B1": ipaddress.IPv4Network("185.204.105.32/27", strict=False),   
    "C1": ipaddress.IPv4Network("185.204.105.60/28", strict=False),   
    "C2": ipaddress.IPv4Network("185.204.105.80/28", strict=False),   
    "C3": ipaddress.IPv4Network("185.204.105.96/28", strict=False),   
    "C4": ipaddress.IPv4Network("185.204.105.112/28", strict=False),  
    "C5": ipaddress.IPv4Network("185.204.105.160/28", strict=False),  
}


def send_teams_message(message, certificate_name): # Envoie un message à un canal Teams via un webhook
    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "text": f"Alert for certificate {certificate_name}: {message}"
    }
    try:
        response = requests.post(WEBHOOK_URL, headers=headers, json=payload)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error sending message to Teams: {e}")

def extract_dates(cert_text): # Extrait les dates de validité d'un certificat à partir du texte du certificat
    not_before = re.search(r'notBefore=(.*)', cert_text)
    not_after = re.search(r'notAfter=(.*)', cert_text)
    if not_before and not_after:
        return (
            datetime.datetime.strptime(not_before.group(1), "%b %d %H:%M:%S %Y GMT"),
            datetime.datetime.strptime(not_after.group(1), "%b %d %H:%M:%S %Y GMT")
        )
    raise ValueError("Unable to parse certificate validity period")

def extract_san(cert_text): # Extrait les Subject Alternative Names (SAN) d'un certificat à partir du texte du certificat
    san_match = re.search(r'X509v3 Subject Alternative Name:(.*)', cert_text, flags=re.DOTALL)
    if san_match:
        san_text = san_match.group(1).strip()
        return re.findall(r'DNS:(.*?)(?:,|$)', san_text)
    return []

def execute_openssl_commands(file_path): # Exécute les commandes OpenSSL pour extraire les informations du certificat
    result_dates = subprocess.run(
        ["openssl", "x509", "-noout", "-in", file_path, "-dates", "-text"],
        capture_output=True, text=True
    )
    cert_text = result_dates.stdout
    not_before, not_after = extract_dates(cert_text)
    alternative_names = extract_san(cert_text)
    return not_before, not_after, alternative_names

def resolve_domain_to_ip(domain_name): # Résout un nom de domaine pour obtenir les adresses IP associées

    domain_name = domain_name.lstrip('*.')
    try:
        resolver = dns.resolver.Resolver()
        answer = resolver.resolve(domain_name, 'A')
        return [str(ip) for ip in answer]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception) as e:
        print(f"Error resolving DNS for {domain_name}: {e}")
    return []

def get_current_cluster():  # Simuler la détermination du cluster actuel
    current_cluster = "B1"  
    return current_cluster

def find_cluster(ip, current_cluster): # Détermine dans quel cluster se trouve une adresse IP donnée
    ip_obj = ipaddress.IPv4Address(ip)
    for name, network in clusters.items():
        if ip_obj in network:
            if name != current_cluster:
                return current_cluster, name  
            return None  
    return None

def verify_cert_validity(not_before, not_after, certificate_name): # Vérifie la validité d'un certificat
    now = datetime.datetime.utcnow()
    remaining_days = (not_after - now).days
    print(f"Certificate validity period for {certificate_name}:")
    print(f"  Valid from: {not_before}")
    print(f"  Valid until: {not_after}")
    
    if now < not_before:
        print(f"The certificate {certificate_name} is not yet valid.")
    elif now > not_after:
        print(f"The certificate {certificate_name} has expired.")
        send_teams_message("The certificate has expired.", certificate_name)
    else:
        print(f"The certificate {certificate_name} is currently valid. {remaining_days} days left before expiration.")

if __name__ == "__main__":
    pem_files = [file for file in os.listdir() if file.endswith(".pem")]

    current_cluster = get_current_cluster()  # Déterminer le cluster actuel

    for pem_file in pem_files:
        print(f"Processing certificate: ./{pem_file}")
        not_before, not_after, alternative_names = execute_openssl_commands(pem_file)
        verify_cert_validity(not_before, not_after, pem_file)

        send_message = False

        if alternative_names:
            print("\nSubject Alternative Names:")
            for name in alternative_names:
                print(f"  {name}")
                ips = resolve_domain_to_ip(name)
                if ips:
                    print(f"    DNS resolved IPs: {', '.join(ips)}")
                    for ip in ips:
                        cluster_error = find_cluster(ip, current_cluster)
                        if cluster_error:
                            print(f"    The IP {ip} for domain {name} is not in the expected cluster {current_cluster}. It is in cluster {cluster_error[1]}.")
                            send_message = True
                            send_teams_message(f"The IP {ip} for domain {name} is not in the expected cluster {current_cluster}. It is in cluster {cluster_error[1]}.", pem_file)
                        else:
                            print(f"    The IP {ip} for domain {name} is in the correct cluster {current_cluster}.")
                else:
                    print(f"    No IP addresses found for {name}.")
                    send_message = True
                    send_teams_message(f"No IP addresses found for domain {name}.", pem_file)
        else:
            print("\nSubject Alternative Names:")
            print("  None")
            send_message = True
            send_teams_message("No Subject Alternative Names found.", pem_file)

        if send_message:
            print("Message sent to Teams.")
        
        print("")


