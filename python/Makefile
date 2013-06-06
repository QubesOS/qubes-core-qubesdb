.PHONY: all
all: build

PYTHON = python

.PHONY: build
build: 
	CC="$(CC)" CFLAGS="$(CFLAGS)" $(PYTHON) setup.py build

.PHONY: install
install:
	CC="$(CC)" CFLAGS="$(CFLAGS)" $(PYTHON) setup.py install \
		$(PYTHON_PREFIX_ARG) --root="$(DESTDIR)" --force

.PHONY: clean
clean:
	rm -rf build/ *.pyc *.pyo *.o *.a *~
