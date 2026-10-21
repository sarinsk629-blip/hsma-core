# Contributing to HSMA Core

First off, thank you for considering contributing to HSMA Core! It is people like you that will make this protocol a reality.

## Architectural Standards

HSMA is built on a strict adversarial audit discipline. All changes to cryptographic primitives, consensus logic, or economic models **must** correspond to a `DECISIONS.md` ledger entry. 

If you are introducing a new feature or fixing a bug:
1. Ensure the change does not violate existing `static_assert` constraints in `params.hpp`.
2. Ensure the change adheres to the Float-Free Numeric Core (DEC-090).
3. Update the `DECISIONS.md` ledger if the change alters protocol semantics.

## Pull Request Process

1. Ensure any install or build dependencies are removed before the end of the layer when doing a build.
2. Update the `README.md` and `docs/` with details of changes to the interface, if applicable.
3. The conformance suite (`./scripts/gate.sh`) must pass with `GATE GREEN` before a PR will be reviewed.
4. You may merge the Pull Request in once you have the sign-off of one core engineer.
