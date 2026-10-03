.PHONY: up down lab logs backend-dev frontend-dev test lint build

up:            ## build and start the stack
	docker compose up --build -d

lab:           ## stack + OWASP Juice Shop lab target
	docker compose --profile lab up --build -d

down:
	docker compose --profile lab down

logs:
	docker compose logs -f backend

backend-dev:
	cd backend && .venv/Scripts/python -m uvicorn app.main:app --reload

frontend-dev:
	cd frontend && npm run dev

test:
	cd backend && .venv/Scripts/python -m pytest -q

lint:
	cd backend && .venv/Scripts/ruff check . && .venv/Scripts/ruff format --check .
	cd frontend && npm run lint && npx tsc --noEmit

build:
	cd frontend && npm run build
