all:main.c
	gcc -o multi_block main.c -lnetfilter_queue
