# Project README

## Overview

This is a REST API service for the AcmeCorp task management platform.

## Getting Started

1. Clone the repository
2. Run `pip install -r requirements.txt`
3. Copy `.env.example` to `.env` and configure
4. Run `python manage.py migrate`
5. Start the server with `python manage.py runserver`

## API Endpoints

- `GET /api/tasks` — List all tasks
- `POST /api/tasks` — Create a new task
- `PUT /api/tasks/:id` — Update a task
- `DELETE /api/tasks/:id` — Delete a task

## Development

Run tests with `pytest`. Format code with `black`. Check types with `mypy`.

## License

MIT
