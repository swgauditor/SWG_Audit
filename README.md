# SWG Audit

Validate the real-world effectiveness of your perimeter security

Live site: [swgaudit.com](https://swgaudit.com)

## Why this exists

Security claims are easy to make but hard to verify.

Most people have no practical way to confirm that their Secure Web Gateway, browser controls, or DLP do what the datasheet says. SWG Audit closes that gap: safe, controlled tests you run yourself, with outcomes you can see.

Defenses that lean on URL filtering are not sufficient anymore. Attackers have evolved significantly and can easily bypass basic URL filtering. SWG Audit makes those realities observable in your environment, without asking you to take anyone’s word for it.

## What you can test

| Area | Focus |
| --- | --- |
| **Phishing** | Lookalike and redirected URLs, client-assembled pages, canvas UIs, content mutation, credential submission |
| **Malware** | Delivery and evasion: formats, nesting, encoding, encryption, chunking, smuggling, related browser behavior |
| **Data theft** | Outbound movement via uploads and evasion channels, including DNS and HTTP path tunneling |
| **Facility abuse** | Whether category and content policy holds under real use |

Every test includes explicit pass and fail criteria.

## How to use

1. Pick a category.
2. Run a test.
3. Read the result against the pass/fail conditions for *your* controls.

Designed to stay simple: one scenario, one action, one clear outcome.

## Safety

Educational and controlled. Use dummy data. Do not submit real credentials or sensitive files.

## Repository

Mintlify source for SWG Audit. Edit and review here, then export and deploy through your normal pipeline to the live host. Site: [swgaudit.com](https://swgaudit.com)
