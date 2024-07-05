# ProjetCert
Ce projet Python vérifie la validité des certificats SSL et identifie les adresses IP associées à leurs noms de domaine.

Installation :
Clonez le dépôt et installez les dépendances nécessaires :

git clone https://github.com/votre-utilisateur/votre-projet.git
cd votre-projet
pip install -r requirements.txt

Assurez-vous d'avoir OpenSSL installé sur votre système :

sudo apt-get update
sudo apt-get install openssl

Utilisation :
Placez vos fichiers PEM contenant les certificats dans le répertoire du projet. Exécutez ensuite le script principal
Avant d'exécuter le script, assurez-vous de configurer l'URL du webhook Teams dans le fichier main.py 

Configurez le cluster actuel (current_cluster) dans le fichier main.py :
current_cluster = "B1"  # Remplacez par le cluster actuel