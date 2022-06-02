# Set to 1 to run OPA through Docker
DOCKER := 0

ifeq ($(DOCKER), 0)
	OPA := opa
else
	OPA := docker run -v $(shell pwd):/policies -w /policies --rm docker.io/openpolicyagent/opa:0.40.0
endif

policy.wasm: client_registration.rego login.rego register.rego
	$(OPA) build -t wasm -e "client_registration/allow" -e "login/allow" -e "register/allow" $^
	tar xzf bundle.tar.gz /policy.wasm
	$(RM) bundle.tar.gz
	touch $@

.PHONY: fmt
fmt:
	$(OPA) fmt -w .

.PHONY: test
test:
	$(OPA) test -v .

.PHONY: lint
lint:
	$(OPA) fmt -d --fail .
	$(OPA) check --strict .
