# Contributing 

All contributions are welcomed, thank you for taking the time to contribute to this project! 
These are a set of guidelines for contributing to the development of Slips [1].

## How can you contribute?

* Run Slips and report bugs and needed features, and suggest ideas
* Pull requests with a solved GitHub issue and new feature
* Pull request with a new detection module.

## Persistent Git Branches

The following git branches in the Slips repository are permanent:

- `master`: contains the stable version of Slips, with new versions at least once a month.
- `develop`: contains the latest unstable version of Slips and also its latest features. All new features should be based on this branch.

## Naming Git branches for Pull Requests

To keep the Git history clean and facilitate the revision of contributions we 
ask all branches to follow concise namings. These are the branch-naming patterns
to follow when contributing to Slips:

- author-bugfix-:        pull request branch, contains one bugfix,
- author-docs-:          pull request branch, contains documentation work,
- author-enhance-:       pull request branch, contains one enhancement (not a new feature, but improvement nonetheless)
- author-feature-:       pull request branch, contains a new feature,
- author-refactor-:      pull request branch, contains code refactoring,

## What branch should you base your contribution to Slips?

As a general rule, base your contributions to the `develop` branch.

## Creating a pull request

Commits:
- Commits should follow the KISS principle: do one thing, and do it well (keep it simple, stupid).
- Commit messages should be easily readable, imperative style ("Fix memory leak in...", not "FixES mem...")

Pull Requests:
- If you have developed multiple features and/or bugfixes, create separate
    branches for each one of them, and request merges for each branch;
- Each PR to develop will trigger the develop Github checks, these checks will run Slips unit tests and integration tests locally in a ubuntu VM and in docker to make sure the branch is ready to merge.
- PRs won't be merged unless the checks pass.
- The cleaner you code/change/changeset is, the faster it will be merged.


## Testing 

This is a very important step. You shouldn't open a PR with code that is not working

Testing slips is done using the following command

```./tests/run_all_tests.sh```

Unit tests finish quickly, but integration tests take a while
Integration tests run Slips on all files in the dataset/ directory and checks for errors and expected evidence

The failing test will tell you exactly which file failed and the reason it did.

Once all tests pass, feel free to open your PR.



## Beginner tips on how to open a PR in Slips

Here's a very simple beginner-level steps on how to create your PR in Slips

1. Clone the Slips repo 
2. In your clone, checkout origin/develop: ```git checkout origin develop```
3. Install slips pre-commit hooks ```pre-commit install```
4. Generate a baseline for detecting secrets before they're committed ```detect-secrets scan --exclude-files ".*dataset/.*|(?x)(^config/local_ti_files/own_malicious_JA3.csv$|.*test.*|.*\.md$)" > .secrets.baseline```
3. Create your own branch off develop using your name and the feature name:  ```git checkout -b <yourname>_<feature_name> develop```
4. Change the code, add the feature or fix the bug, etc. then commit with a descriptive msg ```git commit -m "descriptive msg here" ```
6. If some tests don't pass, it means you need to fix something in your branch. 
7. Push to your own repo: ```git push -u origin <yourname>_<feature_name>``` 
8. Open a PR in Slips, remember to set the base branch as ```develop```.
9. Fill the PR template. 

Some IDEs like [PyCharm](https://www.jetbrains.com/help/pycharm/work-with-github-pull-requests.html) and [vscode](https://levelup.gitconnected.com/how-to-create-a-pull-request-on-github-using-vs-code-f03db28308c4) have the option 
to open a PR from within the IDE. 


That's it, now you have a ready-to-merge PR!

***
[1] These contributions guidelines are inspired by the project [Snoopy](https://raw.githubusercontent.com/a2o/snoopy/master/.github/CONTRIBUTING.md)﻿