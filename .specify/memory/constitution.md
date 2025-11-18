<!--
RAPPORT D'IMPACT DE SYNCHRONISATION
Version: 1.0.0 → 1.1.0
Type de Changement: MINEUR - Ajout conventions de commit
Principes Modifiés: Aucun
Sections Ajoutées:
  - Workflow de Développement > Conventions de Commit
Sections Modifiées:
  - Aucune
Changements:
  - Ajout section "Conventions de Commit" dans Workflow de Développement
  - Spécification format Conventional Commits
  - Interdiction explicite de références aux outils d'IA dans les commits
  - Interdiction de footers "Co-Authored-By" pour outils automatisés
  - Exemples corrects et interdits fournis
Templates Nécessitant Mise à Jour:
  ✅ Aucun - Cette modification n'affecte pas les templates
TODOs de Suivi: Aucun
-->

# Constitution WebSec

## Principes Fondamentaux

### I. Développement Rust-First

Toute implémentation DOIT être écrite en Rust. Ce principe est non-négociable.

**Justification** : Rust fournit des garanties de sécurité mémoire, de concurrence sécurisée et de performance essentielles pour les applications axées sur la sécurité. Le système de types et le modèle d'ownership préviennent des classes entières de vulnérabilités à la compilation.

**Exigences** :
- Utiliser la toolchain Rust stable la plus récente
- Exploiter les idiomes Rust : ownership, borrowing, lifetimes
- Privilégier les abstractions à coût zéro
- Utiliser cargo comme système de build et gestionnaire de dépendances

### II. Développement Piloté par les Tests (NON-NÉGOCIABLE)

Les tests DOIVENT être écrits avant l'implémentation. Le cycle Rouge-Vert-Refactorisation est strictement appliqué.

**Justification** : Le TDD garantit la justesse du code dès le départ, fournit des spécifications exécutables et permet un refactoring sans crainte. Dans un contexte critique pour la sécurité, les tests agissent comme des garde-fous contre les régressions de vulnérabilités.

**Exigences** :
- Écrire le test d'abord → Test échoue (Rouge) → Implémenter le code minimal → Test passe (Vert) → Refactoriser
- Approbation utilisateur des cas de test requise avant le début de l'implémentation
- Couverture minimale : tests unitaires pour toute la logique métier, tests d'intégration pour tous les contrats
- Utiliser le framework `cargo test` avec organisation claire : `tests/unit/`, `tests/integration/`, `tests/contract/`

### III. Design Patterns & Architecture

Une architecture propre et des design patterns établis DOIVENT guider toutes les implémentations.

**Justification** : La sécurité et la maintenabilité nécessitent des structures prévisibles et bien comprises. Les design patterns fournissent des solutions éprouvées et permettent la communication d'équipe via un vocabulaire partagé.

**Exigences** :
- Appliquer les patterns appropriés : Builder, Strategy, Factory, Repository, etc.
- Documenter le choix du pattern et sa justification dans les commentaires du code
- Éviter les anti-patterns : objets God, dépendances circulaires, couplage fort
- Suivre rigoureusement les principes SOLID
- Séparer les préoccupations : logique métier, infrastructure, présentation

### IV. Excellence de Documentation

Chaque module, fonction publique et algorithme non trivial DOIT avoir une documentation complète.

**Justification** : Les outils de sécurité nécessitent une compréhension approfondie par les utilisateurs et mainteneurs. Une documentation manquante ou médiocre crée une surface d'attaque via mauvaise configuration et mauvaise utilisation.

**Exigences** :
- Commentaires Rustdoc (`///`) pour toutes les APIs publiques
- Commentaires inline pour la logique complexe expliquant le "pourquoi" et non le "quoi"
- README avec quickstart, vue d'ensemble de l'architecture et exemples
- Documenter les considérations de sécurité, les modèles de menaces et les hypothèses
- Maintenir un changelog suivant le format Keep a Changelog

### V. Triade Qualité : Qualité, Sécurité, Performance

Le code DOIT respecter des standards élevés en qualité, sécurité et performance. Ce sont des priorités co-égales.

**Justification** : Dans l'outillage de sécurité, les trois dimensions sont critiques. Un outil performant mais non sécurisé est dangereux. Un outil sécurisé mais inutilisable est ignoré. Un outil de haute qualité avec de mauvaises performances ne passera pas à l'échelle.

**Exigences** :

**Qualité** :
- Zéro avertissement compilateur (`#![deny(warnings)]`)
- Lints Clippy appliqués avec paramètres stricts
- Formatage du code via `rustfmt` (vérifié en CI)
- Revue par les pairs obligatoire pour tous les changements

**Sécurité** :
- `cargo audit` passant (pas de vulnérabilités connues dans les dépendances)
- Validation des entrées à toutes les frontières
- Principe du moindre privilège pour les permissions et capacités
- Secrets jamais codés en dur ou loggés
- Checklist de revue de code axée sécurité appliquée
- Modélisation des menaces pour les nouvelles fonctionnalités

**Performance** :
- Benchmark des chemins critiques avec `criterion`
- Profiling avant optimisation (pas d'optimisation prématurée)
- Documenter les caractéristiques et contraintes de performance
- Éviter les allocations dans les hot paths lorsque possible
- Considérer explicitement la complexité algorithmique (Big-O)

## Standards de Sécurité

La sécurité est primordiale pour ce projet. Tout code DOIT adhérer à ces standards :

- **Hygiène des dépendances** : Exécutions régulières de `cargo update` et `cargo audit`
- **Sanitisation des entrées** : Toutes les entrées externes (args CLI, lectures de fichiers, données réseau) validées avant usage
- **Gestion des erreurs** : Jamais de panic en code production ; utiliser `Result` et `Option` correctement
- **Discipline de logging** : Logger les événements de sécurité ; jamais logger de secrets, PII ou données sensibles
- **Defaults sécurisés** : Fail closed, pas open ; opt-in pour les opérations risquées
- **Cryptographie** : Utiliser des bibliothèques validées (rustls, ring, etc.) ; jamais créer sa propre crypto
- **Sécurité de concurrence** : Éviter les data races via le système de types Rust ; documenter les hypothèses de thread-safety

## Workflow de Développement

### Processus de Revue de Code

- Tous les changements via pull requests
- Au moins une revue par les pairs requise
- Le reviewer DOIT vérifier :
  - Tests écrits en premier et échoués avant implémentation
  - Choix du design pattern approprié et documenté
  - Considérations de sécurité adressées
  - Documentation complète
  - Clippy/rustfmt passant

### Portes Qualité (Pipeline CI)

Avant merge, ceux-ci DOIVENT passer :

1. `cargo fmt --check` (formatage)
2. `cargo clippy -- -D warnings` (linting)
3. `cargo test` (tous les tests passent)
4. `cargo audit` (pas de vulnérabilités connues)
5. Build de documentation : `cargo doc --no-deps`

### Gestion de la Complexité

La complexité DOIT être justifiée. Avant d'introduire :

- Une nouvelle dépendance : expliquer pourquoi les solutions existantes sont insuffisantes
- Une nouvelle abstraction : démontrer le besoin clair et le bénéfice
- Un nouveau pattern : justifier par rapport aux alternatives plus simples

Documenter la justification dans la description de la PR.

### Conventions de Commit

Les messages de commit DOIVENT suivre ces règles :

- Format : `type(scope): description` (Conventional Commits)
- Types autorisés : `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`
- Description en français, impératif présent (ex: "ajouter" pas "ajouté")
- Corps du message optionnel pour détails supplémentaires
- **INTERDIT** : Aucune référence à des outils d'IA ou assistants (Claude, ChatGPT, Copilot, etc.)
- **INTERDIT** : Aucun footer "Co-Authored-By" pour des outils automatisés

**Exemples corrects** :
```
feat(detector): ajouter détecteur de bots malveillants
fix(ratelimit): corriger fuite mémoire dans le token bucket
docs: mettre à jour le README avec exemples d'utilisation
```

**Exemples interdits** :
```
❌ feat: ajouter détecteur

   Généré avec Claude Code
   Co-Authored-By: Claude <noreply@anthropic.com>

❌ fix: corriger bug (via ChatGPT)
```

## Gouvernance

Cette constitution supplante toutes les autres pratiques de développement.

**Procédure d'Amendement** :
- Les amendements nécessitent une proposition documentée avec justification
- Consensus d'équipe ou approbation du mainteneur requis
- Incrémentation de version selon versioning sémantique :
  - MAJEUR : Changements de principes incompatibles
  - MINEUR : Nouveau principe ou section ajouté
  - PATCH : Clarifications, corrections de formulation
- Mettre à jour tous les templates dépendants (plan, spec, tasks) lors d'amendement

**Conformité** :
- Toutes les PRs DOIVENT référencer cette constitution durant la revue
- Les vérifications de constitution dans `plan-template.md` DOIVENT être complétées
- Les violations nécessitent une justification explicite dans la table de suivi de complexité
- Les mainteneurs résolvent les disputes via interprétation de la constitution

**Version** : 1.1.0 | **Ratifiée** : 2025-11-18 | **Dernière Modification** : 2025-11-18
