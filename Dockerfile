# Utilisation de l'image Python 3.7
FROM python:3.7

# Définir le répertoire de travail dans le conteneur
WORKDIR /app

# Copier le script principal et les fichiers nécessaires
COPY main.py /app/
COPY requirements.txt /app/
COPY *.pem /app/

# Installer les dépendances définies dans requirements.txt, y compris dnspython
RUN apt-get update && \
    apt-get install -y openssl && \
    pip install -r requirements.txt && \
    pip install dnspython 

# Commande par défaut pour lancer l'application lorsque le conteneur démarre
CMD ["python", "main.py"]