@echo off
cd /d C:\Git\SecurityHeadersAuditor

powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Content .\requirements.md -Raw | codex --ask-for-approval never exec --cd 'C:\Git\SecurityHeadersAuditor' --sandbox workspace-write -"