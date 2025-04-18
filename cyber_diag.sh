#!/bin/bash

set -e

PROJECT_DIR="cyber_diag"
HARVESTER_DIR="theHarvester"
VENV_DIR="venv"
REQUIREMENTS="requirements.txt"

# --- Étape 1 : Dépendances système ---
echo "📦 Installation des paquets système..."
sudo apt update && sudo apt install -y python3 python3-pip python3-venv python3-full nmap git dnsutils

# --- Étape 2 : Clone du repo s’il n’existe pas ---
if [ ! -d "$PROJECT_DIR" ]; then
    echo "⬇️ Clonage du dépôt $PROJECT_DIR..."
    git clone https://github.com/cyber-arthur/cyber_diag.git
fi
cd $PROJECT_DIR
sudo chown -R $USER:$USER $(pwd)

# --- Étape 3 : Installer theHarvester ---
if [ ! -d "../$HARVESTER_DIR" ]; then
    echo "⬇️ Clonage de theHarvester..."
    git clone https://github.com/laramies/theHarvester.git ../$HARVESTER_DIR
    cd $HARVESTER_DIR
    echo "📚 Installation des dépendances de theHarvester..."
    pip install -r requirements/base.txt
    cd ..
else
    echo "✅ theHarvester déjà présent."
fi

# --- Étape 4 : Créer et activer venv ---
if [ ! -d "$VENV_DIR" ]; then
    echo "🧪 Création de l'environnement virtuel..."
    python3 -m venv $VENV_DIR
fi
source $VENV_DIR/bin/activate

# --- Étape 5 : Dépendances Python ---
echo "⬆️ Installation des dépendances Python..."
pip install --upgrade pip
pip install -r $REQUIREMENTS

# --- Étape 6 : Créer .env si manquant ---
if [ ! -f ".env" ]; then
    echo "📝 Création d'un exemple de .env"
    cat <<EOF > .env
SHODAN_API_KEY=your_shodan_api_key
HUNTER_API_KEY=your_hunter_api_key
EOF
    echo "⚠️  N'oubliez pas de remplir vos clés dans .env !"
else
    echo "✅ Fichier .env déjà existant."
fi

# --- Fin ---
echo -e "\n✅ Installation terminée !"
echo "➡️ Vous pouvez maintenant lancer :"
echo "   source venv/bin/activate"
echo "   python main.py --nom entreprise.fr --siren 123456789 --ips 1.2.3.4 5.6.7.8"
