
.PHONY: all clean distclean test test_tls test_ktls test_tls_verbose test_ktls_verbose

all: ktls test.pem ktls_static ktls_boringssl

ktls: ktls.o
	gcc $+ -o $@ -l:libssl.so.1.0.2 -l:libcrypto.so.1.0.2 -lpthread -ldl

ktls_static: ktls.o
	gcc $+ -static -o $@ -lssl -lcrypto -lz -ldl -static-libgcc

ktls_boringssl.o: ktls.c
	gcc $+ -o $@ -c -Iboringssl/include -Wall -Werror

ktls_boringssl: ktls_boringssl.o boringssl/build/ssl/libssl.a boringssl/build/crypto/libcrypto.a
	gcc -o $@ $+ -lz -lpthread -ldl

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

test_ktls_boringssl:
	./ktls_boringssl -k &
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

test_ktls_boringssl_verbose:
	./ktls_boringssl -k &
	sleep 0.2
	echo a | openssl s_client -tls1_2 -cipher AES128-GCM-SHA256 -connect localhost:443 -CAfile test.cert

test_ktls_splice_verbose:
	./ktls -k -s &
	sleep 0.2
	echo a | openssl s_client -connect localhost:443 -CAfile test.cert

test: test_tls test_ktls

boringssl:
	echo "boringssl build requires cmake and golang"
	git clone https://boringssl.googlesource.com/boringssl

boringssl/build: boringssl
	mkdir -p boringssl/build

boringssl/build/Makefile: boringssl/build
	(cd boringssl/build && cmake ..)

boringssl/build/ssl/libssl.a: boringssl/build/Makefile
	(cd boringssl/build && make)

boringssl/build/cryto/libcrypto.a: boringssl/build/ssl/libssl.a

clean:
	-rm -f *.o
	-rm test.key test.cert test.pem
	-rm -rf boringssl

distclean: clean
	-rm -f ktls ktls_static ktls_boringssl
