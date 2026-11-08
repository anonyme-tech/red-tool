# Quickstart

## 1. Installer les dependances
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 2. Demarrer le serveur
```powershell
python server/main.py
```

## 3. Creer un listener local
```powershell
$listener = Invoke-RestMethod `
  -Method POST `
  -Uri http://127.0.0.1:8000/api/listeners/ `
  -ContentType "application/json" `
  -Body '{"name":"Lab Listener","protocol":"https","host":"127.0.0.1","port":8443,"enabled":true}'

$listener.listener_id
```

## 4. Lancer le simulateur
```powershell
python agent/beacon.py --server http://127.0.0.1:8000 --listener <listener_id>
```

## 5. Verifier les stats
```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/listeners/<listener_id>/stats | ConvertTo-Json -Depth 6
Invoke-RestMethod http://127.0.0.1:8000/api/listeners/<listener_id>/agents | ConvertTo-Json -Depth 6
Invoke-RestMethod "http://127.0.0.1:8000/api/listeners/history?listener_id=<listener_id>" | ConvertTo-Json -Depth 6
```

## 6. Uploader un rapport MyAgent vers le listener
Depuis le dossier `..\MyAgent` :

```powershell
dotnet run --project .\MyAgent.csproj -- `
  --json `
  --server http://127.0.0.1:8000 `
  --listener <listener_id>
```

Ou depuis la racine du projet, en une seule commande :

```powershell
.\run_local_audit.ps1
```

Ce helper :
- verifie que l'API vise bien `localhost`
- cree un listener local si besoin
- lance `MyAgent` explicitement
- uploade le JSON vers l'endpoint `audit-reports`
- affiche l'URL API du rapport stocke

## 7. Verifier les rapports d'audit stockes
```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/listeners/<listener_id>/audit-reports | ConvertTo-Json -Depth 6
Invoke-RestMethod http://127.0.0.1:8000/api/listeners/<listener_id>/audit-reports/<report_id> | ConvertTo-Json -Depth 6
Invoke-RestMethod http://127.0.0.1:8000/api/health | ConvertTo-Json -Depth 6
```

## 8. Voir les rapports dans le dashboard
- Ouvre le dashboard `http://127.0.0.1:8000/`
- Va dans l'onglet `Listener`
- Selectionne un listener
- Le panneau `Audit Reports` affiche la liste des rapports et le JSON complet du rapport selectionne

## Base SQLite
- Les listeners et agents simules restent en memoire.
- Les rapports d'audit sont persistés dans SQLite.
- Par defaut, la DB est ecrite dans `%TEMP%\\Red_Team_Persistence\\c2_framework.db`.
- Tu peux forcer un autre chemin avec la variable d'environnement `C2_DB_PATH`.

## Resultat attendu
- Un listener en statut `online`
- Un agent simule enregistre
- Des heartbeats incrementes dans les stats
- Des entrees dans l'historique
- Des rapports d'audit visibles via l'API et stockes en SQLite
