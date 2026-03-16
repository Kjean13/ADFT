"""
Couche fondamentale d'ADFT.

Contient :
  • Les modèles de données unifiés (schéma normalisé)
  • Le système d'ingestion des logs (parseurs)
  • La couche de normalisation des événements

Principe architectural : toutes les couches en aval dépendent
UNIQUEMENT des événements normalisés produits ici.
"""