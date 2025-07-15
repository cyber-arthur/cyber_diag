#!/bin/bash

set -e

# === 0. Dépendances système ===
echo "📦 Installation des dépendances système..."
apt update && apt install -y \
  python3 python3-venv python3-pip python3-full \
  nmap git dnsutils curl build-essential libffi-dev

# === 1. Préparation du projet ===
echo "📁 Accès au dossier cyber_diag..."
cd cyber_diag || { echo "❌ Dossier 'cyber_diag' introuvable."; exit 1; }

# === 2. Cloner theHarvester si absent ===
HARVESTER_DIR="../theHarvester"
[ -d "$HARVESTER_DIR" ] || {
  echo "⬇️ Clonage de theHarvester..."
  git clone https://github.com/laramies/theHarvester.git "$HARVESTER_DIR"
}

# === 3. Création / activation de venv ===
VENV_DIR="venv"
[ -d "$VENV_DIR" ] || {
  echo "🧪 Création de l'environnement virtuel Python..."
  python3 -m venv "$VENV_DIR"
}
source "$VENV_DIR/bin/activate"

# === 4. Installation des dépendances Python ===
echo "⬆️ Installation des dépendances Python..."
pip install --upgrade pip > /dev/null
pip install -r requirements.txt

# === 5. Création du fichier .env si absent ===
[ -f .env ] || {
  echo "📝 Création du fichier .env (exemple)"
  cat <<EOF > .env
SHODAN_API_KEY=your_shodan_api_key
HUNTER_API_KEY=your_hunter_api_key
VT_API_KEY=your_virustotal_api_key
PAPPERS_API_KEY=your_pappers_api_key
EOF
  echo "⚠️  Complétez vos clés API dans .env avant d'exécuter l'analyse."
}

# === 6. Terminé ===
echo -e "\n✅ Installation complète."
echo "➡️ Lancez votre diagnostic avec :"
echo "   source venv/bin/activate"
echo "   python main.py --nom exemple.fr --siren 123456789"
