---
name: commit
description: MUST be used whenever the user asks to commit changes or make a git commit. Always invoke this instead of running `git commit` manually or writing a commit message yourself.
argument-hint: [message]
allowed-tools: Bash(git add:*), Bash(git commit:*), Bash(git status:*), Bash(git diff:*)
model: haiku
context: fork
agent: general-purpose
background: false
---

Staged diff: !`git diff --staged`

Unstaged diff: !`git diff`

Status: !`git status --short`

Commit the current changes directly on the current branch (no branches, no PRs).

Steps:

1. If "Staged diff" is empty, run `git add` on the relevant changed/new files shown in Status, then use `git diff --staged` as the diff to analyze.
2. Read the diff and write a concise conventional-commit message: `type(scope): summary`, using type `fix`, `feat`, `refactor`, `chore`, or `docs` as fits. Keep the summary under ~72 chars, imperative mood, no period.
3. If an argument was given ($ARGUMENTS), use it to guide or override the generated message (e.g. as the summary text or extra context) rather than ignoring it.
4. Run `git commit -m "<message>"` with the final message.
5. Report the commit message and hash used.
