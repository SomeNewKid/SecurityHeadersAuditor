# SecurityHeadersAuditor

This repository is an experiment in using the Codex CLI coding agent to generate
a small Python console application from the instructions in `requirements.md`.

The Python code in `src/security_headers_auditor` should be treated as
agent-generated output, not as finished or production-ready software. The
purpose of this project is to evaluate the Codex CLI workflow, including how it
reads project instructions, makes local edits, runs checks, and reports results.

The generated application crawls a starting website URL and checks each internal
web page for these HTTP security headers:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

The repository is best read as a record of that evaluation. The generated
application code is not recommended for reuse without review, cleanup, tests,
and passing project checks.

## Project Files

- `requirements.md` contains the requirements given to Codex CLI.
- `AGENTS.md` contains coding style and workflow instructions for coding agents.
- `run-codex.bat` runs Codex CLI against `requirements.md`.
- `scripts/setup-dev.ps1` creates or updates the Python virtual environment.
- `scripts/check.ps1` runs formatting, linting, type checking, and tests.
- `src/security_headers_auditor` contains the generated Python application.

## Running Codex CLI

To ask Codex CLI to implement the requirements, run:

```bat
run-codex.bat
```

The batch file reads `requirements.md` and invokes Codex CLI with this project
as the working directory.

## Development Setup

Create or update the virtual environment with:

```powershell
.\scripts\setup-dev.ps1
```

Run project checks with:

```powershell
.\scripts\check.ps1
```

## Running the Generated Application

After setup, run the generated CLI with:

```powershell
.\.venv\scripts\python.exe -m security_headers_auditor "https://www.example.com"
```

Replace `https://www.example.com` with the website to audit.
