.PHONY: run run-root help version check compile test man install clean

run:
	./scanner.py

run-root:
	sudo -E ./scanner.py

help:
	./scanner.py --help

version:
	./scanner.py --version

check:
	./requirements.txt

compile:
	python3 -m compileall nighthawk_app scanner.py

test:
	python3 -m unittest discover -s tests -v

man:
	man -l nighthawk.1

install:
	./install.sh

clean:
	find reports -maxdepth 1 -type f \( -name 'nighthawk_*.html' -o -name 'nighthawk_*.json' -o -name 'nighthawk_*.csv' -o -name 'nighthawk_*.txt' \) -delete
