---
name: Detection rule request
about: Propose a bounded review signal with independent tests
title: "[Rule request] "
labels: ""
assignees: ""
---

English | [Русский](rule_request-RU.md)

## Family, languages and existing coverage

State the security family, affected language/API forms and relevant CWE when
applicable. Which existing rules overlap? Prefer extending a supported detector
to duplicating a signal or increasing a headline rule count.

## Detectable shape and limits

Describe the exact local syntax that can be detected without executing code,
network access or new core dependencies. Separate deployment risks from confirmed
vulnerabilities. List cases that require manual, interprocedural or business-logic
review.

## Independent examples

Provide at least two independently written positive and two safe/context-negative
synthetic examples for each claimed form. Include comments, strings, same-name
user functions, alias rebinding and safer alternatives where relevant.

## Remediation and sources

Explain a safe fix that preserves service/checker behavior and how to test it.
Link authoritative language/API documentation. Do not submit private competition
code, flags, secrets, logs or traffic. See [contributing](../../CONTRIBUTING.md).
