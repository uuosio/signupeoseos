build: wast

clean:
	rm signupeoseos.wast
	rm signupeoseos.wasm

wasm:
	eosio-cpp -I=. -o signupeoseos.wasm signupeoseos.cpp

wast:wasm
	eosio-wasm2wast -o signupeoseos.wast signupeoseos.wasm

deploy:
	cleos set contract signupeoseos ../signupeoseos -p signupeoseos

build_and_deploy: build deploy
