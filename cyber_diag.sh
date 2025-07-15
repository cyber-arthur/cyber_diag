#!/bin/bash

set -e

VENV_DIR="venv"
HARVESTER_DIR="../theHarvester"
REQUIREMENTS="requirements.txt"

echo "🔍 Initialisation de CyberDiag..."

# 1. Cloner theHarvester si absent
[ -d "$HARVESTER_DIR" ] || {
  echo "⬇️ Clonage de theHarvester..."
  git clone https://github.com/laramies/theHarvester.git "$HARVESTER_DIR"
}

# 2. Créer et activer venv
[ -d "$VENV_DIR" ] || {
  echo "🧪 Création de l'environnement virtuel..."
  python3 -m venv "$VENV_DIR"
}
source "$VENV_DIR/bin/activate"

# 3. Installer les dépendances Python
echo "⬆️ Installation des dépendances..."
pip install --upgrade pip > /dev/null
pip install -r "$REQUIREMENTS"

# 4. Télécharger le modèle spaCy français si absent
python -c "import spacy; spacy.load('fr_core_news_sm')" 2>/dev/null || {
  echo "📦 Téléchargement modèle spaCy FR..."
  python -m spacy download fr_core_news_sm
}

# 5. Créer un .env exemple si manquant
[ -f .env ] || {
  echo "📝 Création du fichier .env (exemple)"
  cat <<EOF > .env
SHODAN_API_KEY=your_shodan_api_key
HUNTER_API_KEY=your_hunter_api_key
VT_API_KEY=your_virustotal_api_key
PAPPERS_API_KEY=your_pappers_api_key
EOF
  echo "⚠️  Complétez vos clés API dans .env !"
}

echo -e "\n✅ Installation complète."
echo "➡️ Lancer avec :"
echo "   source $VENV_DIR/bin/activate"
echo "   python main.py --nom exemple.fr --siren 123456789"
