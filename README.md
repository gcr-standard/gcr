# GCR — Clés RSA à graine rejouable, pour des certificats africains

Deux normes, en avant-projet, et le code qui les prouve.

Le but : que des autorités de certification africaines délivrent des certificats X.509 ordinaires,
qui servent à tout et sont lus par tout logiciel, mais dont les clés sortent d'un générateur maîtrisé
de bout en bout. RSA ne change pas. Une seule chose est fixée : la manière de fabriquer la clé.

**Auteur et mainteneur :** Honoré DEMBELE

| Norme | Objet | Texte | Archive (DOI) |
|---|---|---|---|
| GCR-0001 | Génération de clés RSA à graine rejouable | [français](normes/GCR-0001.md) · [English](normes/GCR-0001.en.md) | [10.5281/zenodo.24356091](https://doi.org/10.5281/zenodo.24356091) |
| GCR-0002 | Autorité de certification à clés rejouables | [français](normes/GCR-0002.md) · [English](normes/GCR-0002.en.md) | [10.5281/zenodo.24356095](https://doi.org/10.5281/zenodo.24356095) |

Site : <https://gcr-standard.github.io/gcr/fr/> (présentation, et les deux programmes mis côte à côte sur les graines d'épreuve).

Le code de ce dépôt est archivé par Software Heritage :
[`swh:1:snp:2e19b1b9500a23f470109368dbfd8641ec44248b`](https://archive.softwareheritage.org/swh:1:snp:2e19b1b9500a23f470109368dbfd8641ec44248b;origin=https://github.com/gcr-standard/gcr)
(instantané du 20 novembre 2026).

Statut : avant-projets, version 0.1 du 18 novembre 2026, soumis à commentaires publics. Aucun organisme
de normalisation ne les a homologués. Le texte français fait foi.

## L'idée

Les deux nombres premiers d'une clé RSA sont construits à partir d'une **graine**, par un calcul public
entièrement décrit. La même graine redonne la même clé, sur n'importe quelle machine, avec n'importe quel
programme écrit d'après le texte. Celui qui détient une clé peut donc prouver qu'elle sort de ce calcul
et de rien d'autre : il la refait ailleurs et compare. Un générateur défectueux ou malveillant ne passe
pas cette épreuve.

Le calcul n'est pas nouveau : c'est la construction des premiers prouvables de Shawe-Taylor, publiée dans
FIPS 186-4. La norme la rend obligatoire, la décrit sans renvoi, y joint une fiche de génération et
définit les contrôles de conformité.

## Contenu du dépôt

| Chemin | Rôle |
|---|---|
| `normes/` | Les deux normes (français et anglais), leurs PDF signés, certificats de signature, empreintes et preuves d'horodatage. Voir `normes/LISEZ-MOI.md`. |
| `primes.py`, `keygen.py`, `pem.py` | Implémentation de référence de GCR-0001, en Python, sans dépendance. |
| `rsagraine.py` | La commande : générer une clé, vérifier qu'une graine redonne la clé d'une fiche. |
| `independant/gcr.js` | Seconde implémentation, en JavaScript, écrite d'après le seul texte de la norme. |
| `independant/cas.json` | Vecteurs d'épreuve partagés par les deux implémentations (GCR-0001, annexe A.3). |
| `vecteurs-nist/` | Vecteurs officiels du NIST pour cette méthode. Voir `vecteurs-nist/SOURCE.md`. |
| `autorite/autorite.py` | Outil de référence de GCR-0002 : crée une racine, une autorité délivrante, des certificats. |
| `autorite/controle.py` | Les douze contrôles de GCR-0002 sur une chaîne de certificats. |
| `tests/` | Les épreuves. |

## Essayer

Générer une clé de 3072 bits :

```bash
python3 rsagraine.py generer --bits 3072 --sortie cles/
```

Trois fichiers sont écrits dans `cles/` : la clé privée (`cle.pem`), la graine (`graine.hex`) et la fiche
publique (`fiche.json`). **La graine vaut la clé privée** : qui la tient refait la clé.

Vérifier que la graine redonne bien la clé de la fiche :

```bash
python3 rsagraine.py verifier --graine cles/graine.hex --fiche cles/fiche.json
```

Faire rejouer les vecteurs par la seconde implémentation :

```bash
node independant/gcr.js
```

## Lancer les épreuves

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
```

```bash
.venv/bin/python -m pytest -q
```

Il faut OpenSSL, et Node.js pour l'épreuve de la seconde implémentation. Les épreuves fabriquent une
dizaine de clés, dont une de 4096 bits : comptez quelques minutes.

Elles vérifient que :

- le générateur retrouve les trois cas officiels du NIST (ACVP, RSA KeyGen FIPS 186-4, méthode B.3.2) ;
- les deux implémentations donnent les mêmes clés en 2048, 3072 et 4096 bits ;
- OpenSSL reconnaît les clés, signe et vérifie avec elles ;
- une chaîne racine → autorité délivrante → certificat passe les douze contrôles et la vérification
  stricte d'OpenSSL, et dix chaînes fautives sont chacune arrêtées par le contrôle attendu.

## Limites

- **La graine vaut la clé privée.** Le rejeu se fait par le détenteur ou son auditeur, pas en public.
- **L'implémentation de référence n'est pas en temps constant.** Elle sert à produire et à contrôler des
  clés sur une machine tenue, pas sur une machine qu'un adversaire observe.
- **La qualité de la graine reste celle de l'aléa du système.** Une graine faible donne une clé faible.
- **L'outil d'autorité ne produit pas encore** les listes de révocation ni le registre que GCR-0002 exige,
  et ne délivre que des certificats de serveur.
- **RSA n'est pas éternel.** Un ordinateur quantique assez grand le casse ; les calendriers officiels
  prévoient son retrait dans la décennie 2030.
- **Lu par tous ne veut pas dire reconnu par tous.** Pour qu'un certificat soit tenu de confiance sans
  réglage, sa racine doit figurer dans les magasins de confiance des systèmes et des navigateurs.

## Commenter

Les deux textes sont soumis à commentaires publics. Une observation, une objection, un défaut : ouvrez un
ticket dans ce dépôt. Chaque défaut reconnu est consigné avec sa correction dans l'historique des versions.

## Licences

Les normes sont sous licence Creative Commons Attribution 4.0 International (`LICENSE-SPEC`).
Le code est sous licence Apache 2.0 (`LICENSE`). Les vecteurs du NIST gardent leur statut propre.
