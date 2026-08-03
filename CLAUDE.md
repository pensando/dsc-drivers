# Pensando Repo — Claude Code Context

> This file is loaded automatically by Claude Code on every session.
> It instructs Claude how to assist developers with the branch workflow.

---

## Your Role

When a developer asks about branches, PRs, or git workflow, proactively guide them toward
the branch naming convention. Do not wait to be asked — if you see someone about to create
a branch with the wrong format, correct them before they push.

**Whenever you create or suggest a branch name, you MUST:**

**Step 1 — Resolve the GitHub username:**
```bash
if command -v gh &>/dev/null; then
  LOGIN=$(gh api user --jq .login 2>/dev/null)
else
  # gh not installed — fall back to a cached value
  LOGIN=$(git config github.user 2>/dev/null)
fi
if [[ -z "$LOGIN" ]]; then
  echo "ERROR: Cannot resolve GitHub username."
  echo "  Option A (recommended): install gh CLI and run: gh auth login"
  echo "  Option B: set it manually: git config --global github.user <your-github-login>"
  exit 1
fi
```
`gh api user` returns the exact GitHub org username (e.g. `jsmith-amd`, not `jsmith`).
If `gh` is not installed, cache your username once with `git config --global github.user <your-github-login>`.
**Never infer the username from git config `user.name` or email — the org login may differ.**

**Step 2 — Construct the branch name:**
```
user/${LOGIN}/short-description
```
Include a ticket ID if one exists (e.g. `user/${LOGIN}/fix-rdma-timeout` or `user/${LOGIN}/JIRA-1234-fix-rdma`).
Description must be **ASCII only** — no Unicode, emoji, or special characters. Use hyphens, underscores, or dots as separators. Do not start the description with a dot (`.`) — Git rejects branch names with a leading dot.

**Step 3 — Validate the name matches one of the allowed prefixes:**
- Personal: `^user/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$`
- Team: `^team/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$`
- Bot: `^bot/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$`
- Collab: `^collab/` or `^collab-`
- Auto: `^revert-`, `^copilot/`, `^dependabot/`

Never skip Step 1. A missing or wrong login creates an invalid branch name silently.

---

## Branch Naming Convention

See `AGENTS.md` for the full branch naming reference — format, allowed prefixes, create/push steps.
`AGENTS.md` is the shared baseline read by all AI tools (Claude Code, Copilot, Codex, Gemini).

The short version: `user/<github-login>/<description>` — always resolve login via:
```bash
LOGIN=$(gh api user --jq .login)
```
Never infer from git config or email. A wrong login creates an invalid branch name silently.

---

## Fetch Setup (run once per clone)

With many branches in the repo, `git fetch` can be slow. Scope it to only what you need:

```bash
# Resolve GitHub username (see Step 1 above)
if command -v gh &>/dev/null; then
  LOGIN=$(gh api user --jq .login 2>/dev/null)
else
  LOGIN=$(git config github.user 2>/dev/null)
fi

# Resolve default (trunk) branch
if command -v gh &>/dev/null; then
  DEFAULT=$(gh api repos/pensando/$(basename $(git rev-parse --show-toplevel)) --jq .default_branch 2>/dev/null)
fi
if [[ -z "$DEFAULT" ]]; then
  # Fallback: detect from remote HEAD or ask git
  DEFAULT=$(git remote show origin 2>/dev/null | awk '/HEAD branch/{print $NF}')
fi
DEFAULT=${DEFAULT:-master}  # last resort default

git config --unset-all remote.origin.fetch
git config --add remote.origin.fetch "+refs/heads/${DEFAULT}:refs/remotes/origin/${DEFAULT}"
git config --add remote.origin.fetch '+refs/heads/team/*:refs/remotes/origin/team/*'
git config --add remote.origin.fetch "+refs/heads/user/${LOGIN}/*:refs/remotes/origin/user/${LOGIN}/*"
git config --add remote.origin.fetch '^refs/heads/user/*'
```

This pulls only the default branch, `team/*`, and your own `user/<login>/*` branches.

To fetch a colleague's branch explicitly:
```bash
git fetch origin user/<colleague-login>/branch-name
```

---

## Opening a PR

```bash
# After pushing your branch:
gh pr create \
  --head "user/${LOGIN}/short-description" \
  --title "Short description of change" \
  --body "Description of change"
```

For code review: anyone with write access can push directly to your `user/<login>/*`
branch — you don't need to create a new PR if someone wants to fix a CI failure or
add a small change.

---

## Common Scenarios — How to Help

**Scenario: Developer tries to create `feat/fix-something`**
→ Say: "That branch name will be blocked. Use `user/<login>/fix-something` instead.
  Run: `git checkout -b user/$(gh api user --jq .login)/fix-something origin/<default-branch>`"

**Scenario: Developer asks how to collaborate on someone's branch**
→ Say: "User branches are open — anyone with write access can push.
  Fetch it: `git fetch origin user/<login>/branch-name`
  Check out: `git checkout -b local-fix origin/user/<login>/branch-name`
  Push back: `git push origin HEAD:user/<login>/branch-name`"

**Scenario: Developer's branch was auto-deleted after PR merged**
→ Say: "Branches are auto-deleted when PRs merge. For follow-up work:
  `git checkout -b user/<login>/followup-work origin/<default-branch>`"

**Scenario: Developer asks about deleting their own branch**
→ Say: "You can delete your own branches via the mergers team or the self-service
  deletion tool (coming soon). After PR merge, branches are auto-deleted."

**Scenario: Developer asks why `git fetch` is slow**
→ Say: "Configure scoped fetch using the commands in the Fetch Setup section above.
  This reduces fetch to only the branches you need."

**Scenario: Developer is writing CI automation / a bot**
→ Say: "Use the `bot/<your-bot-account>/<description>` prefix.
  Example: `bot/ci-bot/fix-pr4521`
  This is the designated namespace for automated branches."

**Scenario: Developer's branch was accidentally deleted (not via merge)**
→ Say: "GitHub keeps deleted branch data — go to the repo's branch list or a related PR
  and click 'Restore branch'. There is no official time limit for restoration."

## Further Reading

For the full ruleset design, bypass policies, and org-wide enforcement details, refer to the internal Confluence page:
[GitHub Branch Protection Rulesets](https://amd.atlassian.net/wiki/spaces/EN/pages/1810205147/GitHub+Branch+Protection+Rulesets)