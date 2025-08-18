---
title: Quickstart for GitHub Actions
intro: 'Try out the core features of {% data variables.product.prodname_actions %} in minutes.'
allowTitleToDifferFromFilename: true
redirect_from:
  - /actions/getting-started-with-github-actions/starting-with-preconfigured-workflow-templates
  - /actions/quickstart
  - /actions/getting-started-with-github-actions
  - /actions/writing-workflows/quickstart
versions:
  fpt: '*'
  ghes: '*'
  ghec: '*'
type: quick_start
topics:
  - Fundamentals
shortTitle: Quickstart
---

{% data reusables.actions.enterprise-github-hosted-runners %}

## Introduction

{% data reusables.actions.about-actions %} You can create workflows that run tests whenever you push a change to your repository, or that deploy merged pull requests to production.

This quickstart guide shows you how to use the user interface of {% data variables.product.github %} to add a workflow that demonstrates some of the essential features of {% data variables.product.prodname_actions %}.

{% data reusables.actions.workflow-templates-for-more-information %}

For an overview of {% data variables.product.prodname_actions %} workflows, see [AUTOTITLE](/actions/using-workflows/about-workflows). If you want to learn about the various components that make up {% data variables.product.prodname_actions %}, see [AUTOTITLE](/actions/learn-github-actions/understanding-github-actions).

## Using workflow templates

{% data reusables.actions.workflow-template-overview %}

{% data reusables.actions.workflow-templates-repo-link %}

## Prerequisites

This guide assumes that:
* You have at least a basic knowledge of how to use {% data variables.product.prodname_dotcom %}. If you don't, you'll find it helpful to read some of the articles in the documentation for repositories and pull requests first. For example, see [AUTOTITLE](/repositories/creating-and-managing-repositories/quickstart-for-repositories), [AUTOTITLE](/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/about-branches), and [AUTOTITLE](/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/about-pull-requests).
* You have a repository on {% data variables.product.github %} where you can add files.
* You have access to {% data variables.product.prodname_actions %}.

  > [!NOTE] If the **{% octicon "play" aria-hidden="true" aria-label="play" %} Actions** tab is not displayed under the name of your repository on {% data variables.product.prodname_dotcom %}, it may be because Actions is disabled for the repository. For more information, see [AUTOTITLE](/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository).

## Creating your first workflow

1. In your repository on {% data variables.product.github %}, create a workflow file called `rust-linter.yml` in the `.github/workflows` directory. To do this:
   * If the `.github/workflows` directory already exists, navigate to that directory on {% data variables.product.prodname_dotcom %}, click **Add file**, then click **Create new file**, and name the file `rust-linter.yml`.
   * If your repository doesn't have a `.github/workflows` directory, go to the main page of the repository on {% data variables.product.prodname_dotcom %}, click **Add file**, then click **Create new file**, and name the file `.github/workflows/rust-linter.yml`. This creates the `.github` and `workflows` directories and the `rust-linter.yml` file in a single step.

   > [!NOTE]
   > For {% data variables.product.prodname_dotcom %} to discover any {% data variables.product.prodname_actions %} workflows in your repository, you must save the workflow files in a directory called `.github/workflows`.
   >
   > You can give the workflow file any name you like, but you must use `.yml` or `.yaml` as the file name extension. YAML is a markup language that's commonly used for configuration files.

1. Copy the following YAML contents into the `rust-linter.yml` file:

   ```yaml copy
   name: Rust linter
   run-name: {% raw %}${{ github.actor }}{% endraw %} is running a Rust linter 🦀
   on: [push]
   jobs:
     Lint-Rust-Code:
       runs-on: ubuntu-latest
       steps:
         - name: Check out repository code
           uses: {% data reusables.actions.action-checkout %}
         - name: Install Rust toolchain
           uses: actions-rs/toolchain@v1
           with:
             toolchain: stable
             components: clippy
         - name: Run clippy
           run: cargo clippy -- -D warnings
   ```

   This workflow uses [cargo clippy](https://github.com/rust-lang/rust-clippy), a linter for Rust, to check for common mistakes in the code. It is triggered on every push to the repository. The workflow has one job, `Lint-Rust-Code`, which runs on an Ubuntu runner. The job checks out the code, installs the Rust toolchain with clippy, and then runs clippy. You can learn more about the syntax of workflow files in [AUTOTITLE](/actions/using-workflows/about-workflows#understanding-the-workflow-file), and for an explanation of {% data variables.product.prodname_actions %} contexts, such as `{% raw %}${{ github.actor }}{% endraw %}`, see [AUTOTITLE](/actions/learn-github-actions/contexts).

1. Click **Commit changes**.
1. In the "Propose changes" dialog, select either the option to commit to the default branch or the option to create a new branch and start a pull request. Then click **Commit changes** or **Propose changes**.

   ![Screenshot of the "Propose changes" dialog with the areas mentioned highlighted with an orange outline.](/assets/images/help/repository/actions-quickstart-commit-new-file.png)

Committing the workflow file to a branch in your repository triggers the `push` event and runs your workflow.

If you chose to start a pull request, you can continue and create the pull request, but this is not necessary for the purposes of this quickstart because the commit has still been made to a branch and will trigger the new workflow.

## Viewing your workflow results

{% data reusables.repositories.navigate-to-repo %}
{% data reusables.repositories.actions-tab %}
1. In the left sidebar, click the workflow you want to display, in this example "Rust linter."

   ![Screenshot of the "Actions" page. The name of the example workflow, "Rust linter", is highlighted by a dark orange outline.](/assets/images/help/repository/actions-quickstart-workflow-sidebar.png)

1. From the list of workflow runs, click the name of the run you want to see, in this example "USERNAME is testing out GitHub Actions."
1. In the left sidebar of the workflow run page, under **Jobs**, click the **Lint-Rust-Code** job.

   ![Screenshot of the "Workflow run" page. In the left sidebar, the "Lint-Rust-Code" job is highlighted with a dark orange outline.](/assets/images/help/repository/actions-quickstart-job.png)

1. The log shows you how each of the steps was processed. Expand any of the steps to view its details.

   ![Screenshot of steps run by the workflow.](/assets/images/help/repository/actions-quickstart-logs.png)

   For example, you can see the list of files in your repository:

   ![Screenshot of the "List files in the repository" step expanded to show the log output. The output for the step is highlighted with an orange outline.](/assets/images/help/repository/actions-quickstart-log-detail.png)

The example workflow you just added is triggered each time code is pushed to the branch, and shows you how {% data variables.product.prodname_actions %} can work with the contents of your repository. For an in-depth tutorial, see [AUTOTITLE](/actions/learn-github-actions/understanding-github-actions).

## Next steps

{% data reusables.actions.onboarding-next-steps %}
