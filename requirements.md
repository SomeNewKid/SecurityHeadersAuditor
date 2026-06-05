# Requirements

Before making changes, follow the project instructions in `AGENTS.md`.

Complete the following requirements without waiting for interactive approval unless blocked by an external permission or missing credential.

If implementation requires any Python packages beyond the standard library, update
`pyproject.toml` with the required dependencies. After changing Python package
dependencies, run:

```powershell
.\scripts\setup-dev.ps1
```

Then continue with implementation and verification.

## Build the security_headers_auditor module

Build a CLI application in the existing `src/security_headers_auditor` package.
The application must be executable with:

```powershell
.\.venv\scripts\python.exe -m security_headers_auditor "https://www.example.com"
```

The single command-line argument is the starting website URL.

Given the starting URL, crawl the website and find internal web pages.

- Stay within the starting domain. Do not follow links to other domains.
- Track visited internal URLs and check each internal web page at most once.
- Avoid infinite loops caused by repeated links, circular links, fragments, or
  equivalent normalized URLs.
- Extract links from HTML pages discovered during the crawl.
- Skip non-HTTP and non-HTTPS links such as `mailto:`, `tel:`, and `javascript:`.

For each crawled internal web page, check whether the HTTP response includes all
of these security headers:

```text
Strict-Transport-Security
Content-Security-Policy
X-Content-Type-Options
Referrer-Policy
Permissions-Policy
```

For each web page tested:

- Print the page URL in green if all five required headers are present.
- Print the page URL in red if one or more required headers are missing.
- When headers are missing, print the following line as a comma-separated list
  of the missing header names.

After making the change, run:

```powershell
.\scripts\check.ps1
```

Address any issues reported by the check script until it completes with no errors.
