# Voice & Tone Guidelines

This document defines the voice, tone, and humor boundaries for all user-facing copy in the Code Review Agent.

---

## Voice

The Code Review Agent sounds like:

- A smart, friendly coworker you trust
- Young, confident, feminine, and professional
- Light inside-joke energy for people who work in tech
- Calm and reassuring, never sarcastic or mean

Think: *the senior engineer who gives good code reviews and also happens to be fun to grab coffee with.*

---

## Humor Rules

### Allowed

- Subtle, knowing, shared-experience humor
- Warm, supportive phrasing
- Easter eggs that reward repeat users

### Not Allowed

- Jokes during errors, failures, or BLOCK verdicts
- Mocking the user or their code
- Jokes about breaches, outages, or harm
- Puns that undermine trust
- Anything that would embarrass a junior engineer

---

## Style Rules

### Do

- Write short, conversational sentences
- Use plain language over buzzwords
- Be direct and specific
- Sound human, not robotic

### Don't

- Use em dashes (—)
- Use corporate training tone
- Use chatbot filler like "As an AI" or "Please note"
- Use exclamation marks (one per page max, if ever)
- Use emojis outside verdict status icons

---

## Copy Lint Rules

Avoid these phrases:

| Avoid | Why |
|-------|-----|
| "please", "kindly" | Corporate filler |
| "note that", "it's worth noting" | Passive padding |
| "best practice" | Unless truly necessary |
| "leverage", "utilize" | Buzzwords |
| "simply", "just" | Dismissive |
| "As an AI", "I'm designed to" | Chatbot energy |

---

## Easter Eggs

Easter eggs are small moments of warmth in the UI. They follow strict rules:

### Guidelines

1. **UI-only and ephemeral** — Never in logs, CI output, or exports
2. **Max one per run** — Don't stack jokes
3. **Only shown when explicitly triggered** — Based on verdict and audience
4. **Never on BLOCK** — Seriousness required
5. **Audience-aware** — Beginner mode gets gentler copy

### Curated Examples

| ID | Copy | Verdict | Audience |
|----|------|---------|----------|
| `quiet_win` | "Nothing scary here. We love to see it." | PASS | All |
| `clean_slate` | "A clean review. Someone's been reading the docs." | PASS | Intermediate+ |
| `review_pause` | "Not a fail. Just a pause." | REVIEW_REQUIRED | Beginner |
| `worth_a_look` | "Worth a second look before you ship." | REVIEW_REQUIRED | Intermediate+ |
| `security_pattern` | "Yeah... this is one of those patterns." | REVIEW_REQUIRED | Intermediate+ (high confidence) |

---

## Tone Check

Before showing any user-facing copy, ask:

1. Would this feel okay if a senior engineer said it in a PR review?
2. Would a junior feel supported, not embarrassed?
3. Would a manager be fine seeing this in a screenshot?

**If any answer is no, don't show the message.**

---

## Copilot Integration Notes

When using GitHub Copilot or other AI coding assistants in this repo:

### At the top of files with UI copy

```python
# IMPORTANT:
# Do not generate new UI copy here.
# Only select from predefined copy in EASTER_EGGS or UI_COPY.
# Humor and tone are intentional and curated.
```

### When Copilot suggests off-brand copy

Respond with:

> "Keep the tone like a smart, friendly coworker.
> Subtle tech humor is okay. No jokes during failures.
> Rewrite this."

---

## The Mental Model

This tool is not a chatbot.

This is a calm, human reviewer with good judgment.

**If unsure, prefer clarity over cleverness.**
