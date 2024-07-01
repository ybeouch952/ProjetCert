import subprocess
import re
import datetime
import dns.resolver
import requests

WEBHOOK_URL = "https://ozitem.webhook.office.com/webhookb2/2a908ece-be53-4a2d-b7e0-4b4b5daa1e92@d59105aa-3408-4b50-8581-e3d9fae3b16b/IncomingWebhook/94dd083241184544a14ffdbece447018/4f44b746-73a5-43f7-af3a-b71481bf08ab"  # Mettre l'URL du webhook Teams

def send_teams_message(message):  # envoie un message à un canal Teams via un webhook
    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "text": message
    }
    try:
        response = requests.post(WEBHOOK_URL, headers=headers, json=payload)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error sending message to Teams: {e}")
    # utilise la bibliothèque requests pour effectuer une requête HTTP POST vers l'URL du webhook Teams avec un payload JSON contenant le message à envoyer.

def extract_dates(cert_text):  # extrait les dates de validité d'un certificat
    not_before = re.search(r'notBefore=(.*)', cert_text)
    not_after = re.search(r'notAfter=(.*)', cert_text)
    if not_before and not_after:
        return (
            datetime.datetime.strptime(not_before.group(1), "%b %d %H:%M:%S %Y GMT"),
            datetime.datetime.strptime(not_after.group(1), "%b %d %H:%M:%S %Y GMT")
        )
    raise ValueError("Unable to parse certificate validity period")

def extract_san(cert_text):  # extrait les Subject Alternative Names (SAN) d'un certificat
    san_match = re.search(r'X509v3 Subject Alternative Name:(.*)', cert_text, flags=re.DOTALL)
    if san_match:
        san_text = san_match.group(1).strip()
        return re.findall(r'DNS:(.*?)(?:,|$)', san_text)
    return []

def execute_openssl_commands(file_path):  # exécute les commandes OpenSSL pour extraire à la fois les dates de validité et les SAN d'un certificat
    result_dates = subprocess.run(
        ["openssl", "x509", "-noout", "-in", file_path, "-dates", "-text"],
        capture_output=True, text=True
    )
    cert_text = result_dates.stdout
    not_before, not_after = extract_dates(cert_text)
    alternative_names = extract_san(cert_text)
    return not_before, not_after, alternative_names

def resolve_domain_to_ip(domain_name):  # résout un nom de domaine pour obtenir les adresses IP
    domain_name = domain_name.lstrip('*.')
    try:
        resolver = dns.resolver.Resolver()
        answer = resolver.resolve(domain_name, 'A')
        return [str(ip) for ip in answer]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception) as e:
        print(f"Error resolving DNS for {domain_name}: {e}")
    return []
    # Utilise dns.resolver.Resolver() pour résoudre le nom de domaine en adresses IPv4 et gère plusieurs types d'erreurs pouvant survenir lors de la résolution DNS

def verify_cert_validity(not_before, not_after):  # vérifie la validité d'un certificat en comparant ses dates de validité avec la date et l'heure actuelles
    now = datetime.datetime.utcnow()
    remaining_days = (not_after - now).days
    print(f"Certificate validity period:")
    print(f"  Valid from: {not_before}")
    print(f"  Valid until: {not_after}")
    if now < not_before:
        print("The certificate is not yet valid.")
    elif now > not_after:
        print("The certificate has expired.")
    else:
        print(f"The certificate is currently valid. {remaining_days} days left before expiration.")

if __name__ == "__main__":
    file_path = r"cert_pem.pem"
    not_before, not_after, alternative_names = execute_openssl_commands(file_path)
    verify_cert_validity(not_before, not_after)

    send_message = False  # Indicateur pour savoir si on doit envoyer un message Teams

    if alternative_names:
        print("\nSubject Alternative Names:")
        for name in alternative_names:
            print(f"  {name}")
            ips = resolve_domain_to_ip(name)
            if ips:
                print(f"    IPs: {', '.join(ips)}")
                for ip in ips:
                    if ip.startswith("185.204"):
                        print(f"    The IP address {ip} starts with 185.204. That's good.")
                    else:
                        print(f"    The IP address {ip} is different.")
                        send_message = True
                        send_teams_message(f"The IP address {ip} for domain {name} is different.")
            else:
                print(f"    No IP addresses found for {name}.")
                send_message = True
                send_teams_message(f"No IP addresses found for domain {name}.")
    else:
        print("\nSubject Alternative Names:")
        print("  None")
        send_message = True
        send_teams_message("No Subject Alternative Names found.")

    # Si send_message est vrai, on envoie un message à Teams
    if send_message:
        send_teams_message("Some IP addresses are different or no SANs found.")
