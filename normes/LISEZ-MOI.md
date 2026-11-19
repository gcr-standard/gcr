# Les normes, leurs signatures et leurs preuves

| Fichier | Contenu |
|---|---|
| `GCR-0001.md`, `GCR-0002.md` | Texte de référence des deux normes, en français. **C'est lui qui fait foi.** |
| `GCR-0001.en.md`, `GCR-0002.en.md` | Traduction anglaise. |
| `GCR-0001.pdf`, `GCR-0002.pdf`, `GCR-0001.en.pdf`, `GCR-0002.en.pdf` | Mises en page signées : signature manuscrite de l'auteur et signature électronique (PAdES). La première page de chaque PDF porte l'empreinte de son texte source. |
| `certificat-signature-SCE-….pdf` | Certificat de chaque signature électronique ; il cite l'empreinte du PDF signé. |
| `*.ots` | Preuve d'horodatage OpenTimestamps de chaque fichier, inscrite dans la chaîne Bitcoin. |
| `EMPREINTES-SHA256.txt` | Empreintes SHA-256 des douze fichiers. |

| PDF signé | Certificat de signature |
|---|---|
| `GCR-0001.pdf` | `certificat-signature-SCE-0SCF2QHS.pdf` |
| `GCR-0002.pdf` | `certificat-signature-SCE-BPE8ZJSQ.pdf` |
| `GCR-0001.en.pdf` | `certificat-signature-SCE-196GEMMJ.pdf` |
| `GCR-0002.en.pdf` | `certificat-signature-SCE-VHGY1DWC.pdf` |

## Vérifier

Les empreintes :

```bash
shasum -a 256 -c EMPREINTES-SHA256.txt
```

L'horodatage : déposer sur https://opentimestamps.org la preuve `.ots`, puis le fichier qu'elle accompagne.
Les blocs Bitcoin vont de 976480 à 976487, tous du 18 novembre 2026.

Les PDF signés sont aussi archivés sur Zenodo, à l'identique :
GCR-0001, https://doi.org/10.5281/zenodo.24356091 ; GCR-0002, https://doi.org/10.5281/zenodo.24356095.

Un PDF signé ne se retouche pas : toute modification invalide sa signature. Une correction des normes
donne une nouvelle version, avec ses propres fichiers.
