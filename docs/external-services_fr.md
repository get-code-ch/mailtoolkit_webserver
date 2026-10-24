# Services externes

[English version](external-services.md)

L'analyse peut interroger des services extérieurs sur les liens, les pièces jointes, le serveur d'envoi et les
domaines d'un mail. Tous sont facultatifs : sans eux, l'analyse du mail lui-même (en-têtes, DKIM, SPF, DMARC, liens,
pièces jointes, QR codes…) fonctionne toujours. Cette page résume comment s'inscrire à chacun d'eux, et leurs limites.

Les offres gratuites de Google Safe Browsing, VirusTotal et Spamhaus DQS sont réservées à un **usage non
commercial** : un service public vendu à des clients, ou exploité par une entreprise pour ses propres besoins,
nécessite leurs licences commerciales. Les conditions évoluent : les vérifier sur les sites des services avant de se
fier à cette page.

## Synthèse

| Service | Vérifie | Clé | Limites gratuites |
|---------|---------|-----|-------------------|
| URLhaus (abuse.ch) | hôtes des liens, URLs sur les plateformes partagées | `MTK_ABUSECH_KEY` | usage raisonnable |
| MalwareBazaar (abuse.ch) | SHA-256 des pièces jointes | même clé | usage raisonnable |
| Google Safe Browsing | hôtes des liens, URLs sur les plateformes partagées | `MTK_SAFEBROWSING_KEY` | non commercial, quota journalier du projet Cloud |
| VirusTotal | SHA-256 des pièces jointes, domaines des liens | `MTK_VIRUSTOTAL_KEY` | non commercial, 4 requêtes par minute, 500 par jour |
| Spamhaus ZEN et DBL | serveur d'envoi, domaines | `MTK_SPAMHAUS_DQS_KEY` | non commercial, faible volume |
| SpamCop, SURBL | serveur d'envoi, domaines | aucune | faible volume |
| Registres RDAP | date d'enregistrement des domaines | aucune | — |
| Autorités de certification S/MIME | révocation (OCSP, CRL) | aucune | — |
| Sites des liens | page finale des liens suspects | aucune | — |

Les clés sont passées en variables d'environnement, dans le fichier de secrets lu par [deploy.sh](deploy_fr.md),
plutôt que dans `conf/configuration.json`. Un service sans clé n'est pas interrogé.

## Inscription

### abuse.ch : URLhaus et MalwareBazaar

1. Se connecter sur <https://auth.abuse.ch/> avec un compte existant (GitHub, Google, LinkedIn ou X).
2. Copier l'**Auth-Key** du profil ; la même clé sert pour URLhaus et MalwareBazaar. Générer une nouvelle clé
   invalide la précédente.
3. `MTK_ABUSECH_KEY=<clé>` dans le fichier de secrets, puis `deploy.sh`.

### Google Safe Browsing

1. Créer un projet sur <https://console.cloud.google.com/>.
2. *APIs & Services → Library* : activer la **Safe Browsing API**.
3. *Credentials → Create credentials → API key* ; restreindre la clé à la Safe Browsing API et, si possible, à
   l'adresse du serveur.
4. `MTK_SAFEBROWSING_KEY=<clé>`.

Un usage commercial nécessite l'API payante Web Risk, que ce serveur ne prend pas en charge.

### VirusTotal

1. Créer un compte sur <https://www.virustotal.com/>.
2. La clé se trouve sous **API key** dans le menu du profil.
3. `MTK_VIRUSTOTAL_KEY=<clé>`.

### Spamhaus Data Query Service

1. S'inscrire sur <https://www.spamhaus.com/free-trial/free-data-query-service/> et confirmer l'adresse.
2. La clé DQS est affichée dans le portail Spamhaus.
3. `MTK_SPAMHAUS_DQS_KEY=<clé>`.

Spamhaus refuse les requêtes passant par des résolveurs DNS publics ou partagés, utilisés par la plupart des
hébergeurs cloud : sans cette clé, ZEN et DBL ne répondent souvent pas depuis un serveur hébergé.

### Sans inscription

SpamCop (`bl.spamcop.net`), SURBL (`multi.surbl.org`), les registres RDAP (trouvés grâce à l'annuaire de l'IANA
`data.iana.org`), les serveurs OCSP et CRL des autorités de certification et les sites des liens sont interrogés sans
clé.

## Volume par mail

Le serveur limite les requêtes d'une analyse et garde les réponses en mémoire (un redémarrage vide le cache).

| Service | Par mail | Cache |
|---------|----------|-------|
| URLhaus | 12 hôtes, 20 URLs | 6 h |
| MalwareBazaar | 5 pièces jointes | 6 h |
| Google Safe Browsing | 1 requête (tous les hôtes et URLs ensemble) | 6 h |
| VirusTotal | 4 requêtes (pièces jointes d'abord, puis domaines des liens) | 6 h |
| Listes noires DNS | serveur d'envoi, 15 domaines | — |
| RDAP | 8 domaines | 24 h |
| Suivi des liens | 6 visites automatiques, 15 s au total | — |

Les erreurs ne sont pas mises en cache : l'analyse suivante interroge à nouveau le service.

Avec la clé VirusTotal gratuite, un deuxième mail analysé dans la même minute peut dépasser le quota ; la page
indique alors que le service n'a pas répondu.

## Confidentialité

Les services apprennent ce que le serveur leur demande :

- bases de menaces : noms d'hôtes, empreintes de fichiers et, pour les liens des plateformes partagées (SharePoint,
  GitHub…), les URLs sans leurs paramètres, qui contiennent souvent l'adresse du destinataire ;
- listes noires DNS et RDAP : l'adresse du serveur d'envoi et les domaines du mail ;
- suivi des liens : les sites visités voient une visite depuis l'adresse du serveur, éventuellement la confirmation
  que le mail a été ouvert. Les liens à usage unique (désinscription, confirmation, réinitialisation) ne sont jamais
  suivis automatiquement.

`"reputation": {"disabled": true}` dans la configuration arrête les listes noires, RDAP, les bases de menaces et le
suivi des liens ; `"link_visits": {"disabled": true}` arrête uniquement le suivi des liens ; `"revocation_disabled":
true` les requêtes OCSP et CRL.

## Vérifier un service

Sur la page d'une analyse, vue détaillée, section **Bases de menaces** :

| La page affiche | Signification |
|-----------------|---------------|
| « Aucun lien ni aucune pièce jointe n'est connu de URLhaus, … » | les services listés ont répondu |
| « Sans réponse (clé refusée, quota atteint ou service indisponible) : … » | clé refusée, quota atteint ou service injoignable |
| « Aucune base de menaces n'est configurée sur ce serveur » | aucune clé n'est arrivée jusqu'au serveur |

MalwareBazaar et les requêtes VirusTotal sur les fichiers ne sont faites que pour un mail avec pièces jointes. Les
échecs ne sont pas écrits dans les logs du serveur ; la première ligne des logs indique seulement quelles clés sont
définies (`AbuseCHKey:(set)`).

Une clé peut être testée sans le serveur, par exemple celle d'abuse.ch (HTTP 200 si elle est acceptée, 403
`unknown_auth_key` sinon) :

```sh
curl -s -o /dev/null -w 'HTTP %{http_code}\n' -H "Auth-Key: $(sed -n 's/^MTK_ABUSECH_KEY=//p' /etc/mailtoolkit/secrets.env)" -d host=example.com https://urlhaus-api.abuse.ch/v1/host/
```

`example.com` est répertorié par URLhaus : ne pas l'utiliser comme lien inoffensif dans un mail de test.

## Limites

- Les bases ne connaissent que ce qui a déjà été signalé : un nouveau site de phishing est souvent inconnu pendant
  plusieurs heures.
- Les listes noires DNS, les clés DKIM et les données RDAP sont lues au moment de l'analyse, pas au moment de l'envoi
  du mail.
- Certains registres ne publient pas de service RDAP (`.ch`, `.li`) : l'âge de leurs domaines n'est pas affiché.
- Spamhaus sans clé DQS et SURBL peuvent refuser les requêtes des résolveurs partagés ; la page liste les zones qui
  n'ont pas répondu.
