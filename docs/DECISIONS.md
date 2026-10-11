# Decisions

D1. **Agree the target before building.** Two tests define done: replay the 31 March attack, and live through a normal week of installs. Reason: with any complexity, the target gets forgotten.

D2. **Stop attacks at install time, not on the network.** Reason: Axios was visible before any code ran. Network blocking needs a signed macOS filter and acts too late. The network prototype was set aside.

D3. **Let the package managers do the blocking.** npm `ignore-scripts` and `min-release-age`, pip `only-binary` and `uploaded-prior-to`, uv `exclude-newer`. Reason: they already exist, they work without the hook, and they cover the full dependency tree.

D4. **Upgrade npm 10 to 11.20.0.** Reason: npm 10 silently ignores `min-release-age`. 11.20.0 was chosen because it is itself older than 7 days.

D5. **The hook guards the guards.** It refuses flags, variables, config edits and project config that switch protections off. Reason: a stuck agent will try exactly these.

D6. **Every refusal carries a working command.** Reason: the agent is the user, and "never stuck" is a test.

D7. **No AI in the path.** A small LLM classifier was tested live and never reached a confident answer on the Axios pattern. Reason: a free rule is exact here.

D8. **Fail open, but count it.** Registry slow or an error: allow and log. Reason: never block the agent on the guard's own failure; the daily drill catches real breakage.

D9. **Named source builds are allowed** (`pip install X --no-binary X`, `npm rebuild <trusted> --ignore-scripts=false`). Reason: the 7-day wait still applies, so a hijacked fresh release still can't get in.

D10. **A daily fire drill with self-repair.** Reason: the real risk after launch is drift, not logic. Silent when healthy. A failed or missing drill shows up only as a warning at the start of the next Claude Code session. The drill sends no notification.

D11. **Check every npm, not only the default one** (11 Oct, after one week of real use). Agents put Homebrew's `node@22` first in PATH, and its npm 10.9.9 ignored the 7-day wait. astro 7.3.6 ran about 1 hour old. The drill now replays the attack with each Node keg's npm, and `--fix` upgrades npm inside the keg. Reason: a protection is only as good as the oldest npm an agent can reach.

D12. **The notification says what ran** (11 Oct). The guard reads the version npx actually ran (project `node_modules`, then the npx cache). The note says "stopped", "ran" or "check". Reason: after one week of real use, the log showed a release as "skipped" when it had run. A note that says the opposite of the truth is worse than no note.

D13. **Alert only on the Axios shape** (11 Oct). A new dependency must be brand new (under 30 days) and run an install script. Reason: astro adding rolldown, a long-established package, raised 2 false alarms in one week.

D14. **Stop pnpm, yarn, bun and corepack, and offer the npm command** (11 Oct). Reason: corepack ships with Node and fetches pnpm or yarn, which skip the npm protections. Found by an attacker-minded review, not by the log.
