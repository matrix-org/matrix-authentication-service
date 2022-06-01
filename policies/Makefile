policy.wasm: client_registration.rego login.rego register.rego
	opa build -t wasm -e "client_registration/allow" -e "login/allow" -e "register/allow" $^
	tar xzf bundle.tar.gz /policy.wasm
	rm -f bundle.tar.gz
	touch $@

.PHONY: test
test:
	opa test -v .
