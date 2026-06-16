# CLAUDE.md — Development Agent Instructions

## Project Overview

Backend API for the AcmeCorp logistics platform.
All text in this file uses standard ASCII and printable Unicode only.

## Stack

- Go 1.22 for the API server
- PostgreSQL 16 for persistence
- Redis 7 for caching
- Docker + Kubernetes for deployment

## Coding Guidelines

- Follow Effective Go style
- All exported functions must have godoc comments
- Use `errcheck` and `staticcheck` in CI

## Security Requirements

- All endpoints require authentication via JWT
- Use parameterized queries for all database access
- Validate and sanitize all external inputs
- Run `gosec` on every PR

## Git Workflow

Feature branches -> PR -> Code review -> Merge to main -> Auto-deploy to staging
