# SiteSentinel 🛡️

A tiny, free, scheduled security-advisory watchdog for personal websites. It checks official **PHP** and **WordPress** news feeds and the **CISA Known Exploited Vulnerabilities** catalog each day, then emails configured administrators about potentially relevant notices.

**Important:** This is an *advisory monitor*, not a vulnerability scanner. A notice does **not** mean your sites are vulnerable or compromised. It cannot inspect installed versions or detect intrusions. It currently tracks PHP/WordPress advisories and CISA entries mentioning those products, not every dependency on your servers.

## Keep emails private, even with a public repository

Recipients and sending credentials are read from **GitHub Actions repository secrets**. Never put email addresses, passwords, or API keys in files, commits, Issues, or workflow logs.

1. Open **Settings → Secrets and variables → Actions → New repository secret** in this repository.
2. Add these secrets:

| Secret | Example / purpose |
|---|---|
| `ALERT_TO` | Comma-separated admin email addresses (private) |
| `ALERT_FROM` | Sender address, approved by your mail provider |
| `SMTP_HOST` | Your mail provider's SMTP server |
| `SMTP_PORT` | `587` for STARTTLS or `465` for implicit TLS |
| `SMTP_USERNAME` | SMTP account login |
| `SMTP_PASSWORD` | Dedicated SMTP app password or token — **not** your main login password |

Each recipient will see the other recipients in the email's To field. They will **not** appear in the public repository. Use a shared mailbox or change sending logic to individual messages later if recipient privacy from each other is also required.

3. Open **Actions → SiteSentinel security advisories → Run workflow** to test.
4. Inspect the run summary. If configured, the initial run sends advisories from the previous 14 days and records delivered IDs in `state/seen.json` to prevent repeated alerts.
5. It then runs daily around **07:17 UTC**. GitHub may delay scheduled jobs. If your repo is inactive for an extended period, GitHub may disable schedules, so check the Actions tab periodically.

If any email secret is missing, the checker will **not** send an email or mark alerts as delivered. Its run log will say so.

## Failure behavior

- An SMTP failure causes the workflow to fail; unsent alerts are not marked seen.
- A single failed advisory feed produces an email warning if SMTP is configured.
- If all feeds fail, the workflow fails and retains state.
- This first version has **no independent heartbeat**: a stopped or disabled GitHub schedule will not notify you. Add external heartbeat monitoring during the later security audit.
- `state/seen.json` contains only public advisory identifiers, never private addresses.

## Local dry run

Requires Python 3.12+ and only standard-library modules:

```bash
python sitesentinel.py
```

Without SMTP environment variables, it fetches recent notices but does not send or update state.

## Sources

- [PHP official news](https://www.php.net/)
- [WordPress security news](https://wordpress.org/news/category/security/)
- [CISA known exploited vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

## Roadmap (optional)

After a website audit: document installed software versions, expand relevant vendor feeds, verify backups, monitor uptime and certificate expiry, add an external missed-run alert, and consider private per-recipient emails.
