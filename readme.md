# Service Contract Validator

This application validates a service.yaml file against a platform contract and reports
any issues in a way that helps a product team fix them quickly.

## Enrolment process

Each product team must:
* create download this repository
* create a new branch
* add a `service.yaml` file with the alerts 
* create a Pull Requests

## service.yaml File Reference 

| Field | Type | Required | Values | Description |
| :--- | :---: | ---: | ---: | ---: | 
| schema_version | string | yes | 1.0 | Schema version for compatibility |
| service_name | string | yes | | Name of the service impacted |
| owner | string | yes | yes | Name of the team managing this service |
| env | string | yes| dev, staging, prod | In which environment the app is |
| data_sensitivity | string | yes | low, medium, high | Level of sensibility of the data |
| backup_enabled | bool (false by default) | no | true, flase | Is backup enabled ? |
| cost_center | string | no | | In which cost this project is part of |
| alerts | list | yes | (see below) | List of alerts |


## Alerts Catalog 

Users-impacted alerts (High priority)
* high_5xx_rate
* p99_latency_breach 
* auth_errors 
* request_failures 
* health_checks_failures 

Infrastructure alerts 
* cpu_high 
* memory_pressure 
* disk_full  

## Validation rules 
We can find below the list of validation rules we implement. For each rule, you will also find the error message.

1. REQUIRED_FIELDS  
Rule: Required fields must be present and non-empty

```
FAIL: REQUIRED_FIELDS
Service: MY_SERVICE

Issue: "Some fields are missing"
Missing fields: field1 (str), field2 (str)

Fix: Required fields must be present and non-empty 
```

2. ENVIRONMENT_NAME_ALERT
Rule: env must be one of dev, staging and prod
```
FAIL: ENVIRONMENT_NAME_ALERT
Service: MY_SERVICE

Issue: "env name must be dev, staging or prod"
Found: "found value"

Example: "env: prod"
```

3. DATA_SENSITIVITY_NAME_ALERT
Rule: data_sensitivity must be one of low, medium and high 
```
FAIL: DATA_SENSITIVITY_NAME_ALERT
Service: MY_SERVICE 

Issue: "data_sensitivity must be low, medium or high"
Found: "found value"

Example: "data_sensitivity: medium"
```

4. PROD_SYMPTOM_ALERT 
Rule: if env is prod, there must be at least, one users-impacted alert in alerts list 
```
FAIL: PROD_SYMPTOM_ALERT
Service: MY_SERVICE

Issue: "No symptom-based alerts found"
Found: ["cpu_high", "disk_full"]

Need: At least one alert about user-facing symptoms
Examples: "5xx_rate_high", "p99_latency_breach", "auth_errors", "request_failures", "health_checks_failures
Fix: Add an alert that monitors service behaviour, not just resources

```

5. RUNBOOK_URL_ALERT 
Rule: if env is prod, required runbook_url 
```
FAIL: RUNBOOK_URL_ALERT
Service: MY_SERVICE

Issue: "For production environment, a runbook url is required"

Need: At least one runbook url must be specified.
```

6.  BACKUPS_ENABLED_ALERT
Rule: if env is prod and data_sensitivity is high, backups_enabled: true 
```
FAIL: BACKUPS_ENABLED_ALERT
Service: MY_SERVICE

Issue: "For production environment, a backup_enabled to true is required"

Need: At least one backup_enabled must be specified.
```

## Exceptions 

If some alerts must be deactivated for a temporary time for any reason, the exceptions should be added the exeptions.yaml file as a list element 

- rule: "VALIDATION_RULE"
  service: service-name 
  reason: "Text describing the reason why this exception"
  expires: "expiration-date of this exception"
  approved_by: "team name that approved this exception"

In case the exception is applied, a message will be added to outputs. The exit code is 0, even in enforce mode.

```
[EXCEPTION] exception is applied
Reason: THIS_IS_THE_REASON
expires: EXPIRATION_DATE
approved_by: APPROVED_BY
```

## ENFORCEMENT MODES

Command: $ python3 validation.py --mode=warn resource.yaml exceptions.yaml

- `warn` mode: print findings with an exit code of 0
- `enforce` mode: print finding with a non-zero exit code


## Schema evolution notes

In case we need new fields and rules, we can implement a new validator class named ValidatorV2 that extends ValidatorV1. This keeps versions isolated — a breaking change in v2 never touches v1 logic. The idea is to read schema_version first, then route to the right validator class or function. Each version owns its own set of rules and required fields:

```python 
def get_validator(schema_version: str):
    validators = {
        "1.0": ValidatorV1,
        "2.0": ValidatorV2,
    }
    if schema_version not in validators:
        raise ValueError(f"Unsupported schema_version: '{schema_version}'")
    return validators[schema_version]()
```

## Rollout plan

Phase 1: `schema_version: "2.0"` will be deployed while keeping a full V1 compatibility. A depreciation warning will be displayed when a v1 file is detected.

Phase 2: We can pick 2 repositories with `env: dev` or `env: staging` — nothing in prod. We can migrate their service.yaml to v2, run the validator in --mode=warn first, then switch to --mode=enforce. This validates that the new rules are sound and that the error messages are clear before touching anything critical.

Phase 3: We can roll out in --mode=warn first across 6 more repositories, 2 or 3 at a time. We give teams a few days to fix findings on their own. Then we move to --mode=enforce only once a repo has zero warnings. 

Phase 4: We migrate the remaining 2 repositories, typically the most critical or most complex ones. Once all 10 are green in enforce mode, we remove v1 support from the validator or lock it behind a hard deprecation error.

Exceptions management: We keep a shared exceptions.yaml at the org level for teams that need more time, with a firm expires date no longer than 30 days out. This prevents exceptions from becoming permanent workarounds. It enables tracking progress in a simple table — repo name, current schema version, validator mode, and status — so nothing gets forgotten across 10 repos.


## CI Configuration

The github actions will run the validator with different modes depending on the branch where the Pull Request is targetting.

If the PR is targetting the `main` branch, the `enforce` mode is used. In other cases, in particular a 10-repo rollout, the `warn` mode is used. 

``` YAML
- name: Set validation mode
  run: |
    if [ "${{ github.base_ref }}" = "main" ]; then
      echo "MODE=enforce" >> $GITHUB_ENV
    else
      echo "MODE=warn" >> $GITHUB_ENV
    fi
```








      
