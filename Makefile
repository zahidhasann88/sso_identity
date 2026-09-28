# Common development tasks. Requires a .env (see .env.example).
.DEFAULT_GOAL := help
.PHONY: help install env keys migrate migrations run test demo lint fmt check audit dbshell up down reset-db

help:  ## List available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	 | awk -F':.*?## ' '{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install:  ## Install development dependencies
	pip install -r requirements/dev.txt

env:  ## Create .env from the template if absent
	@test -f .env || (cp .env.example .env && echo "created .env - review it")

keys:  ## Generate the RSA signing keypair (4096-bit)
	python manage.py generate_jwt_keys --size 4096

migrations:  ## Create migrations for model changes
	python manage.py makemigrations

migrate:  ## Apply migrations
	python manage.py migrate

run:  ## Start the development server
	python manage.py runserver 0.0.0.0:8000

test:  ## Run the full test suite
	python manage.py test identity

demo:  ## Run the live attack-simulation harness
	python scripts/security_demo.py

lint:  ## Lint with ruff
	ruff check .

fmt:  ## Auto-fix lint findings
	# No `ruff format`: this codebase is lint-managed, not formatter-managed, so
	# it would rewrite every file. Run it only as a deliberate separate commit.
	ruff check --fix .

check:  ## Django system checks, deployment profile
	python manage.py check --deploy

audit:  ## Report advisories against the production dependency set
	pip-audit --requirement requirements/prod.txt --strict

dbshell:  ## Open a psql shell on the configured database
	python manage.py dbshell

up:  ## Start the Postgres container
	docker compose up -d db

down:  ## Stop the compose stack
	docker compose down

reset-db:  ## Drop and recreate the schema, then migrate (destructive)
	python manage.py flush --noinput && python manage.py migrate
