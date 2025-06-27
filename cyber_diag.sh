#!/bin/bash

set -e

PROJECT_DIR="cyber_diag"
HARVESTER_DIR="theHarvester"
VENV_DIR="venv"
REQUIREMENTS="requirements.txt"


# --- Étape 1 : Installer theHarvester ---
if [ ! -d "../$HARVESTER_DIR" ]; then
    echo "⬇️ Clonage de theHarvester..."
    git clone https://github.com/laramies/theHarvester.git
else
    echo "✅ theHarvester déjà présent."
fi

# --- Étape 2 : Créer et activer venv ---
if [ ! -d "$VENV_DIR" ]; then
    echo "🧪 Création de l'environnement virtuel..."
    python3 -m venv $VENV_DIR
fi
source $VENV_DIR/bin/activate

# --- Étape 3 : Dépendances Python ---
echo "⬆️ Installation des dépendances Python..."
cd $HARVESTER_DIR/
echo "📚 Installation des dépendances de theHarvester..."
pip install -r requirements.txt
cd ..
pip install --upgrade pip
pip install -r $REQUIREMENTS
python -m spacy download fr_core_news_sm

# --- Étape 4 : Créer .env si manquant ---
if [ ! -f ".env" ]; then
    echo "📝 Création d'un exemple de .env"
    cat <<EOF > .env
SHODAN_API_KEY=your_shodan_api_key
HUNTER_API_KEY=your_hunter_api_key
VT_API_KEY=your_virustotal_api_key
EOF
    echo "⚠️  N'oubliez pas de remplir vos clés dans .env !"
else
    echo "✅ Fichier .env déjà existant."
fi

# --- Fin ---
echo -e "\n✅ Installation terminée !"
echo "➡️ Vous pouvez maintenant lancer :"
echo "   source venv/bin/activate"
echo "   python main.py --nom entreprise.fr"
