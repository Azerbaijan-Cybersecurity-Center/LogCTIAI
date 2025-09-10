VENV?=.venv
PY?=$(VENV)/bin/python
PIP?=$(VENV)/bin/pip

.PHONY: setup install lint fmt test scan scan-all ui help doctor scan-file

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

ui:
	. $(VENV)/bin/activate; streamlit run src/ui/streamlit_app.py

help:
	@echo "Targets:" && \
	echo "  make setup       # Create venv and install deps" && \
	echo "  make scan        # Offline demo scan -> PDF" && \
	echo "  make scan-all    # Demo scan with CTI (uses VT_API_KEY)" && \
	echo "  make scan-file FILE=path CTI_MAX=-1 RATE=0.8 BURST=1 SAVE=50 # Full control" && \
	echo "  make ui          # Launch Streamlit UI" && \
	echo "  make lint|fmt|test" && \
	echo "  make doctor      # Quick environment check"

doctor:
	@python3 -c 'import sys; print("Python:", sys.version.split()[0]); assert sys.version_info[:2] >= (3,10)' || (echo "Python 3.10+ required" && exit 1)
	@[ -f .env ] || echo "Note: .env not found (optional). Copy .env.example -> .env"
	@[ -n "$$VT_API_KEY" ] || echo "Note: VT_API_KEY not set; CTI calls will be disabled."

# Example: make scan-file FILE=data/sample_ips.txt CTI_MAX=-1 RATE=0.8 BURST=1 SAVE=25
scan-file:
	@[ -n "$(FILE)" ] || (echo "Usage: make scan-file FILE=path [CTI_MAX=-1] [RATE=0.8] [BURST=1] [SAVE=50]" && exit 1)
	. $(VENV)/bin/activate; \
		$(PY) -m src.cli scan-ips $(FILE) --out data/processed --cti-max $${CTI_MAX:--1} \
		--cti-rate $${RATE:-0.8} --cti-burst $${BURST:-1} --save-every $${SAVE:-50}
