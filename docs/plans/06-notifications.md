# Plan 06 — Discord notifications + watch mode

Three pieces: webhook alerts (simplest), watch mode (the loop that generates alerts), and an optional bot (query sift from Discord). Build webhook + watch first; the bot is a nice-to-have on top.

## 6a. Webhook alerts

### Library
None. A Discord webhook is an HTTP POST of a JSON body to a URL you paste in. Use `net/http` + the embeds format.

### How
Add to `Settings`:
```go
DiscordWebhookURL string
NotifyMinScore    float64  // only alert on repos at/above this
```
A `notify.go` with a `Notifier` that formats a repo into a Discord embed: name + link, score and the part breakdown, top `HotFiles` (from plan 3a — the lead list), contacts, known-advisory note (plan 4a), and the flag reasons. Batch multiple repos into one message (Discord allows up to 10 embeds per call; respect the rate limit and the ~2000-char/field limits). Keep the token and any secrets out of the payload.

### Done when
- With a webhook URL set, finishing a run (or a watch tick) posts the new/changed high-scorers to Discord with their scores, lead files, and reasons.
- No webhook URL → silently skipped, no error.

## 6b. Watch mode

### Why
Fresh code means fresh bugs. A repo you've already triaged becomes interesting again the moment a commit touches a file that contains sinks. Watch mode re-checks shortlisted/scanned repos on a schedule and alerts when something worth re-reading changed.

### How
`sift watch [--scene …] [--interval 6h]` (plan 5 command), or a background loop inside `serve`. On each tick, for repos with status `shortlist`/`digging`/`new` that pass filters:
1. Cheap check first: compare the default-branch head SHA (already stored as `Enriched.HeadSHA`) against the current head (one lightweight call). Skip if unchanged.
2. If it moved, look at which files changed (`/repos/{o}/{r}/compare/{old}...{new}`). If any changed path matches a sink profile's extensions (or, better, was a `HotFile`), re-run enrich+scan for that repo.
3. If its score crossed `NotifyMinScore` or a hot file changed, fire a 6a alert.

Store `last_watched` and the last-seen SHA so ticks are incremental and quiet when nothing moved. Default interval generous (6h) — this is a background watcher, not a poller.

### Done when
- A watched repo whose head SHA is unchanged does zero scan work on a tick.
- A commit touching a sink-bearing file triggers a re-scan and (if it clears the threshold) a Discord alert naming the changed file.

## 6c. Discord bot (optional)

### Library
`github.com/bwmarrin/discordgo`.

### How
A long-running bot (its own `sift bot` command, or inside `serve`) with slash commands that read the DB:
- `/top [scene] [n]` — ranked list.
- `/repo <name>` — the detail card: score parts, hot files, contacts, reasons, known advisories.
- `/shortlist` — current shortlist.
- `/run <scene>` — kick off a run (guard this: only allow configured user IDs; it spends API budget).
Reuse the same embed formatter as 6a. Keep the bot read-mostly; gate anything that triggers work or reveals contacts behind an allow-list of Discord user IDs in settings.

**Where it talks and where its secrets live.** Alerts and bot replies carry leads on unreported bugs and maintainer contacts, so post only to a private server you own (or DMs), never a shared one, and make bot replies ephemeral where Discord allows. A webhook URL is a write credential and the bot token is a full credential: on the VPS both come from `/etc/sift/sift.env` (plan 8b), not `settings.json`, and neither is ever returned by the API or logged. Check the allow-list against the interaction's user ID on the server side, not by hiding commands.

### Done when
- `/top mcp 10` returns the ranked list in Discord.
- `/run` is restricted to allow-listed users and reports when the run finishes.

## Files
- `notify.go` — embed formatting + webhook POST (shared by watch and run-finish).
- `watch.go` — the tick loop.
- `bot.go` — discordgo wiring (optional).
- `config.go` — webhook URL, min score, bot token, allow-list.
