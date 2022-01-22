.PHONY: all check test ptest clean

all :

check : test
test : 02 03
	./test.sh
	#./test-ws.sh

02 :
	./02-subscribe-argv-errors.py
	./02-subscribe-filter-out.py
	./02-subscribe-qos1.py
	./02-subscribe-format.py
	./02-subscribe-null.py
	./02-subscribe-verbose.py

03 :
	./03-publish-argv-errors.py
	./03-publish-options-file.py
	./03-publish-qos0-empty.py
	./03-publish-qos1-properties.py
	./03-publish-qos1.py
	./03-publish-repeat.py
	./03-publish-socks.py
	./03-publish-stdin-file.py
	./03-publish-stdin-line.py

ptest :
	./test.sh
	#./test-ws.sh
	./test.py

clean:
