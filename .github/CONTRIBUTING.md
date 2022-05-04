# Contributing to Slips Development

All contributions are welcomed, thank you for taking the time to contribute to this project! 
These are a set of guidelines for contributing to the development of Slips[^1].

## How can you contribute?

* Run Slips and report bugs and needed features, and suggest ideas
* Pull requests with a solved GitHub issue and new feature
* Pull request with a new detection module.

## Persistent Git Branches

The following git branches permanent in the Slips repository:

- `master`: contains the stable version of Slips, with new versions at least once a month.
    All new features should be based on this branch.
- `develop`: contains the latest unstable version of Slips and also its latest features.

## Naming Git branches for Pull Requests

To keep the Git history clean and facilitate the revision of contributions we 
ask all branches to follow concise namings. These are the branch-naming patterns
to follow when contributing to Slips:

- name-bugfix-<>:        pull request branch, contains one bugfix,
- name-docs-<>:          pull request branch, contains documentation work,
- name-enhance-<>:       pull request branch, contains one enhancement (not a new feature, but improvement nonetheless)
- name-feature-<>:       pull request branch, contains a new feature,
- name-refactor-<>:      pull request branch, contains code refactoring,

## What branch should you base your contribution to Slips?

As a general rule, base your contribution on the `master` branch.

## Creating a pull request

Commits:
- Commits should follow the KISS principle: do one thing, and do it well (keep it simple, stupid).
- Commit messages should be easily readable, imperative style ("Fix memory leak in...", not "FixES mem...")
Pull Requests:
- If you have developed multiple features and/or bugfixes, create separate
    branches for each one of them, and request merges for each branch;
- The cleaner you code/change/changeset is, the faster it will be merged.

***
[^1] These contributions guidelines are inspired by the project [Snoopy](https://raw.githubusercontent.com/a2o/snoopy/master/.github/CONTRIBUTING.md) 
