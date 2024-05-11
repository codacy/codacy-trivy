# Codacy Trivy

This is the docker engine we use at Codacy to have [Trivy](https://github.com/aquasecurity/trivy) support.

## Usage

You can create the docker by doing:

  ```bash
  docker build -t codacy-trivy:latest .
  ```

The docker is ran with the following command:

  ```bash
  docker run -it -v $srcDir:/src codacy-trivy:latest
  ```

## Generate Docs

 1. Update the version in `go.mod`
 2. Install the dependencies:

```bash
go mod download
```

 3. Run the DocGenerator:

```bash
go run ./doc-generator.go &&\
scala-cli doc-generator.sc
```

## Test

We use the [codacy-plugins-test](https://github.com/codacy/codacy-plugins-test) to test our external tools integration.
You can follow the instructions there to make sure your tool is working as expected.

## Versioning

The latest version of this docker image will be updated daily with new versions of Trivy's vulnerability DBs. The update process keeps the version tag.

For example, if the latest tag is `1.2.3`, then each day the image content for that tag is updated.

If you're using this docker image please guarantee that you're always using the latest version, and that you always pull the image, to make sure you're not exposed to new vulnerabilities.

The `latest` tag is also available but you should avoid using it, as it is harder to track which version of the image is running and more difficult to roll back properly.

## Updating Trivy

After updating the Trivy version in `go.mod`, you need to update the version in [CircleCI's configuration](/.circleci/config.yml) to make sure the vulnerabilities DB downloaded are compatible.

## What is Codacy?

[Codacy](https://www.codacy.com/) is an Automated Code Review Tool that monitors your technical debt, helps you improve your code quality, teaches best practices to your developers, and helps you save time in Code Reviews.

### Among Codacy’s features

- Identify new Static Analysis issues
- Commit and Pull Request Analysis with GitHub, BitBucket/Stash, GitLab (and also direct git repositories)
- Auto-comments on Commits and Pull Requests
- Integrations with Slack, HipChat, Jira, YouTrack
- Track issues in Code Style, Security, Error Proneness, Performance, Unused Code and other categories

Codacy also helps keep track of Code Coverage, Code Duplication, and Code Complexity.

Codacy supports PHP, Python, Ruby, Java, JavaScript, and Scala, among others.

### Free for Open Source

Codacy is free for Open Source projects.
