VENV?=.venv
PY?=$(VENV)/bin/python
PIP?=$(VENV)/bin/pip

.PHONY: setup install lint fmt test scan

setup:
	python -m venv $(VENV)
	. $(VENV)/bin/activate; $(PIP) install -r requirements.txt

install:
	. $(VENV)/bin/activate; $(PIP) install -r requirements.txt

lint:
	. $(VENV)/bin/activate; $(PY) -m ruff check . || true

fmt:
	. $(VENV)/bin/activate; $(PY) -m ruff format . || true

test:
	. $(VENV)/bin/activate; pytest -q || true

scan:
	. $(VENV)/bin/activate; $(PY) -m src.cli scan-ips data/sample_ips.txt --out data/processed --no-cti

scan-all:
	. $(VENV)/bin/activate; $(PY) -m src.cli scan-ips data/sample_ips.txt --out data/processed --cti-max -1
