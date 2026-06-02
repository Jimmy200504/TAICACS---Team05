# Week 15 Integration Results

Owner: Fan Sheng-Wei  
Branch: `data`  
Date: 2026-06-02

## Scope

This Week 15 result file records the data and evaluation artifacts prepared for integration. It does not claim live n8n or Ollama execution results. The focus is to provide a larger labeled dataset, a broader prompt-injection attack set, and metric helpers that can consume prediction records once the workflow and LLM tracks produce them.

## Implemented Artifacts

- `data/raw/normal_emails.csv`
- `data/raw/spam_emails.csv`
- `data/raw/malicious_emails.csv`
- `data/processed/email_eval_set.jsonl`
- `data/attacks/prompt_injection_cases.jsonl`
- `data/attacks/struqlite_attack_set.jsonl`
- `src/evaluation/build_attack_set.py`
- `src/evaluation/run_eval.py`
- `src/evaluation/metrics.py`
- `tests/test_eval_metrics.py`
- `scripts/run_local_eval.sh`
- `scripts/demo_seed_data.sh`

## Local Validation

Command:

```bash
./scripts/run_local_eval.sh
```

Output:

```text
# Data/Evaluation Summary

Raw CSV seed emails: 90
Evaluation seed emails: 90
Prompt-injection attack cases: 24
Total records prepared: 114

Raw CSV label distribution:
  - malicious : 30
  - normal    : 30
  - trash     : 30

Evaluation label distribution:
  - malicious : 30
  - normal    : 30
  - trash     : 30

Attack expected-label distribution:
  - malicious : 20
  - normal    : 2
  - trash     : 2

Attack type distribution:
  - attachment_name_injection                  : 1
  - base64_instruction                         : 1
  - benign_marketing_schema_attack             : 1
  - benign_security_training_with_warning_text : 1
  - benign_with_injection_text                 : 1
  - confidence_manipulation                    : 1
  - control_characters                         : 1
  - delimiter_spoofing                         : 1
  - fake_developer_message                     : 1
  - fake_json_completion                       : 1
  - fake_n8n_command                           : 1
  - fake_policy_update                         : 1
  - fake_system_message                        : 1
  - html_hidden_injection                      : 1
  - ignore_instruction                         : 1
  - markdown_fenced_fake_output                : 1
  - mfa_code_instruction_attack                : 1
  - multilingual_chinese                       : 1
  - multilingual_spanish                       : 1
  - nested_delimiter_spoofing                  : 1
  - role_play_attack                           : 1
  - schema_change_request                      : 1
  - tool_invocation_attack                     : 1
  - unicode_spacing_attack                     : 1

Source type distribution:
  - synthetic_attack_seed : 24
  - synthetic_seed        : 90

Validation checks:
  - raw CSV files are readable
  - required webhook fields present
  - expected_label is one of normal/trash/malicious
  - urls and attachment_names are JSON arrays
  - message_id values are non-empty and unique within each file

Validation status: passed
```

## Unit Tests

Command:

```bash
python3 -m unittest discover -s tests
```

Output:

```text
.....
----------------------------------------------------------------------
Ran 5 tests in 0.000s

OK
```

## Week 16 Handoff

The expected prediction record fields for future metric calculation are:

- `message_id`
- `expected_label`
- `predicted_label` or `label`
- `confidence`
- `final_action`
- `validation_status`

The current metric helpers can calculate accuracy, malicious recall, normal false positive rate, manual review rate, and attack success rate once these fields are collected from n8n/LLM runs.
