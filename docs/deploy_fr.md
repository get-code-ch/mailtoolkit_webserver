# Déployer avec deploy.sh

[English version](deploy.md)

`deploy.sh` reconstruit l'image et recrée le container `mail-analyzer` avec les mêmes options que la section
[Deployment](../README.md#deployment) du README, plus les secrets (clés des bases de menaces, tokens d'administration
et d'ingestion) lus dans un fichier conservé hors du projet. Les mailboxes de `data/` sont conservées.

## Utilisation

```sh
./deploy.sh          # reconstruit à partir de la copie actuelle
./deploy.sh --pull   # git pull --ff-only d'abord
```

Le script peut être lancé depuis n'importe quel dossier : il retrouve le projet à partir de son propre emplacement.

| Variable          | Valeur par défaut                | Rôle |
|-------------------|----------------------------------|------|
| `MTK_PROJECT_DIR` | le dossier de `deploy.sh`        | sources, utilisées pour construire l'image |
| `MTK_RUNTIME_DIR` | `MTK_PROJECT_DIR`                | dossier contenant `conf/`, `ssl/` et `data/`, monté dans le container |
| `MTK_SECRETS`     | `/etc/mailtoolkit/secrets.env`   | secrets transmis au container avec `--env-file` |

Ces variables sont lues uniquement dans l'environnement du script. Écrites dans le fichier de secrets, elles
arriveraient dans le container, pas dans le script.

Exemple, avec la configuration, le certificat et les mailboxes dans `/opt` :

```sh
MTK_RUNTIME_DIR=/opt/mailtoolkit_webserver ./deploy.sh
```

## Fichier de secrets

Les secrets restent hors du projet : ils ne sont ainsi jamais commités ni envoyés dans le contexte de build Docker.
`secrets.env.example` sert de modèle :

```sh
sudo install -d -m 750 -o "$USER" -g "$USER" /etc/mailtoolkit
install -m 600 secrets.env.example /etc/mailtoolkit/secrets.env
```

- Une ligne `VAR=valeur` par variable, sans guillemets ni espaces autour du `=` : Docker prend la ligne telle quelle.
  Les lignes commençant par `#` sont ignorées.
- Une valeur vide désactive le service : le serveur l'ignore.
- Le fichier doit appartenir à l'utilisateur qui lance le script (pas à `root` en 600) : c'est la commande `docker`
  qui le lit, pas le démon. Il ne doit pas être lisible par les autres utilisateurs (600 ou 640).
- Les valeurs sont lues à la création du container : après une modification, relancer `deploy.sh`, un
  `docker restart` ne suffit pas.

Les variables sont décrites dans [Services externes](external-services_fr.md) et dans la section
[Configuration](../README.md#configuration) du README.

## Ce que fait le script

1. Vérifie, avant de toucher au container en service, que `conf/configuration.json`, `ssl/server.crt` et
   `ssl/server.key` de `MTK_RUNTIME_DIR` sont lisibles, que `data/` est modifiable, et que le fichier de secrets
   existe et n'est pas lisible par tous. Le container tourne avec l'utilisateur courant (`--user`) : ces fichiers
   doivent donc lui appartenir.
2. Lance `git pull --ff-only` avec `--pull`.
3. Construit l'image avant d'arrêter le container en service, pour réduire l'interruption.
4. Supprime le container et en démarre un nouveau : ports 25, 587, 80 et 443, `conf/` et `ssl/` en lecture seule,
   `data/` en écriture, `--restart unless-stopped`.
5. Affiche les logs après 3 secondes.

## Vérifier le déploiement

La première ligne des logs affiche la configuration ; les secrets y apparaissent comme `(set)` lorsqu'ils sont
arrivés jusqu'au serveur, sans leur valeur :

```
Configuration {... ThreatIntel:{AbuseCHKey:(set) SafeBrowsingKey: VirusTotalKey:} ... AdminToken:(set)}
SMTP (MX) listening on :25
SMTP (submission) listening on :587
HTTPS listening on :443
HTTP (redirect) listening on :80
```

Les noms des variables reçues par le container, sans leurs valeurs :

```sh
docker exec mail-analyzer env | grep -o '^MTK_[A-Z_]*='
```

## Erreurs

| Message | Correction |
|---------|------------|
| `<dossier>/ssl/server.key absent ou illisible par <utilisateur>` | copier le fichier, ou donner le dossier à l'utilisateur : `sudo chown -R "$USER": <dossier>` |
| `<dossier>/data absent ou non modifiable par <utilisateur>` | idem, `data/` et ses sous-dossiers doivent appartenir à l'utilisateur |
| `<fichier> absent ou illisible : voir secrets.env.example` | créer le fichier de secrets, appartenant à l'utilisateur |
| `<fichier> est accessible à tous : chmod 600 ou 640` | `chmod 600 <fichier>` |

Ces erreurs, comme un build qui échoue, laissent le container en service intact.

## Limites

- Le port 465 (`smtps`) n'est pas publié ; ajouter `-p 465:465` au script s'il est activé dans la configuration.
- Un container lancé à la main avec d'autres options ou variables les perd : mettre les variables dans le fichier de
  secrets.
- Les mailboxes sont celles du `data/` monté : faire pointer `MTK_RUNTIME_DIR` vers un autre dossier ne les déplace
  pas.
