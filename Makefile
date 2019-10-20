all:
	gcc -std=gnu99 main.c -o dns
test:
	python3 test.py
