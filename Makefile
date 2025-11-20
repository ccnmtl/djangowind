PY_DIRS=djangowind
VE ?= ./ve
REQUIREMENTS ?= test_reqs.txt
SYS_PYTHON ?= python3
PY_SENTINAL ?= $(VE)/sentinal
WHEEL_VERSION ?= 0.45.1
PIP_VERSION ?= 25.3
MAX_COMPLEXITY ?= 12
PY_DIRS ?= $(APP)
DJANGO ?= "Django==4.2.19"

FLAKE8 ?= $(VE)/bin/flake8
PIP ?= $(VE)/bin/pip

all: flake8

clean:
	rm -rf $(VE)
	find . -name '*.pyc' -exec rm {} \;
	rm -rf node_modules

$(PY_SENTINAL):
	rm -rf $(VE)
	$(SYS_PYTHON) -m venv $(VE)
	$(PIP) install pip==$(PIP_VERSION)
	$(PIP) install --upgrade setuptools
	$(PIP) install wheel==$(WHEEL_VERSION)
	$(PIP) install --no-deps --requirement $(REQUIREMENTS) --no-binary cryptography
	$(PIP) install "$(DJANGO)"
	touch $@

test: $(REQUIREMENTS) $(PY_SENTINAL)
	./ve/bin/python runtests.py

flake8: $(PY_SENTINAL)
	$(FLAKE8) $(PY_DIRS) --max-complexity=$(MAX_COMPLEXITY)

.PHONY: flake8 test clean
