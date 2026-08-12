# Issue Tracker: GitHub

Issues and PRDs for this repository live in GitHub Issues at
`github.com/wgpsec/context1337`. Use the `gh` CLI from the repository root.

## Conventions

- Create: `gh issue create --title "..." --body "..."`.
- Read: `gh issue view <number> --comments`.
- List: `gh issue list --state open --json number,title,body,labels,comments`.
- Comment: `gh issue comment <number> --body "..."`.
- Label: `gh issue edit <number> --add-label "..."`.
- Close: `gh issue close <number> --comment "..."`.

When a skill says to publish to the issue tracker, create a GitHub issue in this
repository. Infer repository identity from `git remote -v`.
