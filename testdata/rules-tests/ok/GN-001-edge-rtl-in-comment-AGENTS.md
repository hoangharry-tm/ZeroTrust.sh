# AGENTS.md — Multilingual Project Instructions

## Project Overview

This project supports internationalization for Arabic and Hebrew markets.

## Language Support Notes

The codebase uses RTL (right-to-left) text in the UI layer only. The agent instruction
files themselves contain only ASCII English instructions. RTL rendering is handled
by the CSS `direction: rtl` property in the frontend — not by Unicode BIDI characters
in source code or configuration files.

## Instructions for the AI Agent

- Generate code with standard ASCII characters only in variable names and comments
- UI string values may contain Arabic/Hebrew text in `.po` translation files
- Do NOT insert BIDI control characters into Python, JavaScript, or configuration files

## Development Guidelines

Follow the standard git workflow. All PRs require two approvals.
Run the full test suite before opening a PR: `make test-all`
