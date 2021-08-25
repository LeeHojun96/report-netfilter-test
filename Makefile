nfqnl_test : nfqnl_test.c
	gcc -o nfqnl_test nfqnl_test.c -lnetfilter_queue

clean :
	rm nfqnl_test
