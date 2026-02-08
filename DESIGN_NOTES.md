# Design Notes

This document explains how I approached the design of Code Review Agent and
what problems I was trying to explore.

It is not a user guide.

---

## The problem I cared about

AI is increasingly embedded in workflows where mistakes can have real impact.
In these settings, fully automated decisions are often the wrong answer.

I wanted to build something that helps people think more clearly about risk,
instead of telling them what to do.

---

## Why severity and confidence are separate

Many tools collapse risk into a single severity score.

In practice, impact and certainty are different things.

This project treats severity as a measure of potential impact and confidence as
a measure of how sure the agent is about what it found. Keeping them separate
allows for more realistic review and escalation decisions.

---

## Verdicts as guidance, not commands

The agent returns one of three verdicts:

- **PASS**  
  No concerning patterns detected with meaningful confidence.

- **REVIEW REQUIRED**  
  Potential risk depending on context or assumptions.

- **BLOCK**  
  High-confidence, high-impact issues commonly associated with exploitation.

This mirrors how real security and governance decisions are made.

---

## Blast radius and downstream thinking

Issues are not evaluated in isolation.

The agent considers how a finding could affect data, systems, or users downstream.
This helps avoid narrow fixes that miss broader impact.

---

## Human override and auditability

Automated decisions are never final.

The system is designed to support review, override, and explanation.
Each run can produce structured output that is useful for audits or post-incident
analysis.

---

## UX and trust

Security tools often create anxiety or alert fatigue.

I deliberately aimed for a calm interface with progressive disclosure and clear
language. Trust and psychological safety are treated as core design requirements.

---

## Limits and tradeoffs

This tool does not guarantee complete coverage or correctness.
It does not replace expert review.

It is meant to support judgment, not act as an authority.

---

## Broader context

This project is part of a broader interest in judgment-aware AI agents and
governance-first AI systems.
