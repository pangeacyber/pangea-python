# Contributing

Currently, the setup scripts only have support for Mac/ZSH environments.
Future support is incoming.

To install our linters, simply run `./dev/setup_repo.sh`
These linters will run on every `git commit` operation.

## Publishing

Publishing this monorepo's packages to PyPI is handled via a private GitLab CI
pipeline. This pipeline is triggered when a Git tag is pushed to the repository.
Git tags should be formatted as `package-name/vX.Y.Z`, where `package-name` is
the name of the package to publish (e.g. `pangea-django`, `pangea-sdk`) and
`vX.Y.Z` is the [PEP 440][]-compliant version number to publish.[^1]

### Publishing pangea-django

1. Update the `version` in `packages/pangea-django/pyproject.toml`.
2. Update the release notes in `packages/pangea-django/CHANGELOG.md`.
3. Author a commit with this change and land it on `main`.
4. `git tag -m pangea-django/v1.0.0 pangea-django/v1.0.0 0000000`. Replace
  `v1.0.0` with the new version number and `0000000` with the commit SHA from
  the previous step.
5. `git push --tags origin main`.

From here the GitLab CI pipeline will pick up the pushed Git tag and publish
the package to PyPI.

### Publishing pangea-sdk

1. Update `version` in `packages/pangea-sdk/pyproject.toml`.
2. Update `__version__` in `packages/pangea-sdk/pangea/__init__.py`.
3. Update the release notes in `packages/pangea-sdk/CHANGELOG.md`.
4. Author a commit with these changes and land it on `main`.
5. `git tag -m pangea-sdk/v1.0.0 pangea-sdk/v1.0.0 0000000`. Replace `v1.0.0`
  with the new version number and `0000000` with the commit SHA from the
  previous step.
6. `git push --tags origin main`.

From here the GitLab CI pipeline will pick up the pushed Git tag and publish
the package to PyPI.

## Contributors

- Andrés Tournour (andres.tournour@gmail.com). Code.
- Glenn Gallien (glenn.gallien@pangea.cloud). Code and docs.
- David Wayman (david.wayman@pangea.cloud). Code and docs.

[PEP 440]: https://peps.python.org/pep-0440/

[^1]: Prior to the introduction of pangea-django, there was only package,
pangea-sdk, in the monorepo so Git tags were created without a package name
qualifier. These tags will remain for historical purposes but new ones should
not be created going forward.
