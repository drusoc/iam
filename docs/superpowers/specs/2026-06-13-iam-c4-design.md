# IAM C4 Diagram Design

## Goal

Create one HTML page with Mermaid C4 diagrams describing IAM at a high level.

## Scope

- System Context: user, web application, IAM, Google OAuth.
- Container: IAM HTTP API, PostgreSQL, Redis, Google OAuth, web application.
- User cases: Google sign-in, authorization-code exchange, current-session lookup, session refresh, logout.
- No packages, classes, use-case objects, repositories, handlers, or other source-code structure.

## Presentation

The page contains two switchable views: `System Context` and `Container`. Mermaid renders both diagrams in the browser. Relation labels describe user-facing flows and protocols without endpoint-level detail.

## Verification

Open the HTML page in a browser and verify both views render, switch correctly, and remain readable at desktop width.
