# Recording script — RLS Doctor (60 seconds)

Assets in this folder:

| File | What it shows |
| --- | --- |
| `rls-demo.gif` | `rls-doctor demo` — disposable Postgres, score 29/100, proven cross-owner read |
| `rls-score.gif` | `check --schema-file ... --score --badge` — offline score reveal |
| `screenshot-check.png` | 1270×760 terminal: catalog findings |
| `screenshot-probe.png` | 1270×760 terminal: probe proof |
| `*.cast` | asciinema sources (trimmed, spinner-free) |

## 60-second screen recording

| Time | Shot | Narration |
| --- | --- | --- |
| 0:00–0:05 | Terminal, big font, dark theme | "Your RLS says no. This proves it. Can user A read user B's rows?" |
| 0:05–0:12 | Type `npx rls-doctor demo`, run | "One command. No database, no credentials, no config." |
| 0:12–0:25 | Let the audit scroll; pause on `RLS Score: 29/100` | "It finds the structural failures: RLS disabled on a granted table, reachable TRUNCATE, unconditional public writes." |
| 0:25–0:40 | Pause on `PROVEN: Role authenticated reads rows across 2 distinct owner_id values` | "Then it stops analyzing and proves it — impersonating the app role inside a read-only transaction that always rolls back." |
| 0:40–0:48 | Show `The container was removed. No database was modified.` | "Disposable Postgres. Gone. Nothing was written." |
| 0:48–1:00 | Run `rls-doctor check --schema-file migration.sql --score --badge` | "In CI, audit your migrations offline and fail the build on high findings. No database needed." |

Hook line to open with: **"Can user A read user B's rows?"**
Close: **"Don't trust your RLS. Prove it. npx rls-doctor demo."**

## Regenerating the GIFs

```bash
# from a neutral directory (npx resolves the local package inside its own repo)
asciinema rec --overwrite --cols 100 --rows 30 --idle-time-limit 1 -q \
  -c 'npx -y rls-doctor@0.5.2 demo 2>/dev/null | while IFS= read -r line; do printf "%s\n" "$line"; sleep 0.05; done' \
  rls-demo.cast
agg --font-size 15 --theme asciinema --fps-cap 8 --speed 2 --last-frame-duration 4 \
  rls-demo.cast rls-demo.gif
```

Screenshots: render `docs/assets/terminal-preview.svg` and `probe-preview.svg`
centered on `#0f1115` at 1270×760 with headless Chromium.

Never record against a real database. The demo's container is disposable by
construction; everything else here is offline.
