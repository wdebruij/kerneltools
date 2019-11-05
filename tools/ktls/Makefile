
.PHONY: all clean distclean test test_tls test_ktls test_tls_verbose test_ktls_verbose

all: ktls test.pem

ktls: ktls.o
	gcc $+ -o $@ -l:libssl.so.1.0.2 -l:libcrypto.so.1.0.2 -lpthread -ldl

%.o: %.c
	gcc -ggdb -c -Wall -Werror $< -o $@

test.pem:
	openssl req -nodes -new -x509 \
		-subj "/CN=localhost/" \
		-keyout test.key -out test.cert
	cat test.key test.cert > test.pem

test_tls:
	./ktls &
	sleep 0.2
	echo a | socat stdio openssl-connect:localhost:443,pf=ip6,cert=test.pem,cafile=test.cert

test_tls_verbose:
	./ktls &
	sleep 0.2
	echo a | openssl s_client -connect localhost:443 -CAfile test.cert

test_ktls:
	./ktls -k &
	sleep 0.2
	echo a | socat stdio openssl-connect:localhost:443,pf=ip6,cert=test.pem,cafile=test.cert

test_ktls_splice:
	./ktls -k -s &
	sleep 0.2
	echo a | socat stdio openssl-connect:localhost:443,pf=ip6,cert=test.pem,cafile=test.cert

test_ktls_verbose:
	./ktls -k &
	sleep 0.2
	echo a | openssl s_client -connect localhost:443 -CAfile test.cert

test_ktls_splice_verbose:
	./ktls -k -s &
	sleep 0.2
	echo a | openssl s_client -connect localhost:443 -CAfile test.cert

test: test_tls test_ktls

clean:
	-rm -f *.o
	-rm test.key test.cert test.pem

distclean: clean
	-rm -f ktls
