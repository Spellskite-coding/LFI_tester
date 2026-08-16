# LFI_tester

Scanner de vulnérabilités **Local/Remote File Inclusion** en Python pur (aucune dépendance tierce), avec crawling automatique, contournement de WAF et génération de rapports.

> Outil de test pour audits de sécurité autorisés (pentest, CTF, labo personnel). Ne l'utilisez jamais contre une cible sans autorisation explicite.

## Fonctionnalités

- **Zéro dépendance externe** : uniquement la bibliothèque standard de Python 3.8+ (`urllib`, `html.parser`, `concurrent.futures`, `http.cookiejar`, `json`). Pas de `pip install` requis.
- **Crawling automatique** : découvre les formulaires et les liens internes du site (profondeur bornée, même origine) pour élargir la surface testée au-delà de la seule page fournie.
- **~370 payloads** par point d'injection (arsenal complet par défaut), générés en combinant des préfixes de traversée (profondeurs multiples, encodage URL simple/double/triple, Unicode overlong `%c0%af`, bypass de filtre non récursif `....//`, séparateurs Windows, bypass Tomcat `..;/`) avec une liste étendue de cibles (fichiers systèmes multi-distributions, configs Apache/nginx/PHP/MySQL, logs pour poisoning, sessions, `.env`/`.git`/`.svn`, wrappers PHP `php://filter`/`expect://`/`data://`/`zip://`/`phar://`, cibles Windows, `WEB-INF/web.xml`, etc.). Un mode `--quick` (20 payloads triés sur le volet) permet une passe de triage rapide.
- **Détection de blocage WAF** (codes 403/406/429/501 + signatures de réponse) et **contournement automatique** : en cas de blocage, le payload est ré-envoyé avec des variantes (encodage URL, `..;/` façon Tomcat, casse alternée, suffixe null byte) jusqu'à trouver une variante qui passe.
- **Scan concurrent** (thread pool configurable) avec retries réseau et jitter optionnel pour rester discret. Échoue rapidement (pas de retry avec backoff) sur une cible clairement injoignable plutôt que d'insister inutilement.
- **Rapports** JSON et HTML autonomes (sans dépendance externe) résumant chaque payload testé, son statut et le contournement utilisé le cas échéant.
- Teste à la fois les **paramètres d'URL existants**, une **liste de noms de paramètres courants** (`page`, `file`, `path`, …) sur les URL sans paramètres, et **chaque champ de formulaire** individuellement (les autres champs gardent leur valeur par défaut, au lieu d'écraser tous les champs avec le même payload).

### Arsenal complet vs. mode rapide

L'arsenal complet (défaut) est pensé pour un audit approfondi : chaque cible/WAF a ses propres angles morts, donc plus de variété = plus de chances de passer. Sur une cible distante avec de la latence réseau, un scan complet avec crawling + devinette de paramètres peut prendre du temps (des dizaines de minutes selon la surface découverte) — augmentez `--workers`, réduisez `--max-pages`, ou visez directement les paramètres connus avec `--no-crawl --no-guess-params` pour aller plus vite. Pour une passe de reconnaissance rapide sur beaucoup de cibles, utilisez `-q/--quick` (arsenal réduit à haute probabilité de succès).

## Utilisation

```bash
python3 LFI_tester.py -u http://cible.exemple/ [options]
```

### Options principales

| Option | Description |
|---|---|
| `-u, --url` | URL cible (obligatoire) |
| `-t, --timeout` | Timeout par requête (défaut : 10s) |
| `-w, --workers` | Threads concurrents (défaut : 8) |
| `--delay` | Délai aléatoire (0..delay s) entre requêtes |
| `--max-pages` | Nombre max de pages crawlées (défaut : 20) |
| `--no-crawl` | Ne teste que l'URL donnée, sans crawling |
| `--no-forms` | Désactive le test des formulaires |
| `-q, --quick` | Arsenal réduit (~20 payloads) pour une passe de triage rapide |
| `--no-guess-params` | Désactive le test des noms de paramètres courants |
| `--no-bypass` | Désactive les tentatives de contournement WAF |
| `--cookie` | En-tête `Cookie` brut |
| `-H, --header` | En-tête additionnel `"Nom: valeur"` (répétable) |
| `--proxy` | Proxy HTTP(S), ex. `http://127.0.0.1:8080` (Burp/ZAP) |
| `-o, --output` | Rapport JSON |
| `--html-report` | Rapport HTML |
| `-y, --yes` | Ignore la confirmation de périmètre |
| `-v, --verbose` | Affiche chaque test, pas seulement les résultats positifs |

### Exemple

```bash
python3 LFI_tester.py -u http://127.0.0.1:8000/ --html-report rapport.html -y
```

## Sécurité et éthique

Au lancement, l'outil demande une confirmation explicite si la cible n'est pas `localhost`/`127.0.0.1`, pour rappeler que les tests doivent être autorisés. `-y` permet de sauter cette confirmation en environnement automatisé (CI, labo local, etc.).

## Limites connues

- Les wrappers PHP (`php://filter`, `expect://`) ne fonctionnent que contre une cible PHP réellement vulnérable ; ils sont inclus pour la couverture mais ne garantissent rien contre une autre stack.
- Le contournement de WAF est heuristique : il augmente les chances de succès mais ne garantit pas de passer tous les WAF (notamment les WAF commerciaux avec inspection contextuelle avancée).

## Développement et tests

Ce script a été développé et validé contre un labo web volontairement vulnérable maison (Python stdlib pur, 4 niveaux de protection croissante par catégorie de faille : aucune protection, filtre naïf, WAF avec angle mort, et implémentation sécurisée). Ce labo est un outil de développement séparé, non inclus dans ce dépôt.
