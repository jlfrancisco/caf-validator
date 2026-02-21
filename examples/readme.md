# valid-prod file
```
OK: All validation rules passed.
```

# invalid-no-alert file
```
FAIL: REQUIRED_FIELDS
Service: my-service

Issue: "Some fields are missing"
Missing fields: owner (str)

Fix: Required fields must be present and non-empty

FAIL: PROD_SYMPTOM_ALERT
Service: my-service

Issue: "No symptom-based alerts found"
Found: ['cpu_high', 'disk_full']

Need: At least one alert about user-facing symptoms
Examples: "high_5xx_rate", "p99_latency_breach", "auth_errors", "request_failures", "health_checks_failures"
Fix: Add an alert that monitors service behaviour, not just resources

FAIL: RUNBOOK_URL_ALERT
Service: my-service

Issue: "For production environment, a runbook url is required"

Need: At least one runbook url must be specified.

Found 3 issue(s).
```
