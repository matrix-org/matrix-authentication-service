# Set to 1 to run OPA through Docker
DOCKER := 0

ifeq ($(DOCKER), 0)
	OPA := opa
	OPA_RW := opa
else
	OPA := docker run -i -v $(shell pwd):/policies:ro -w /policies --rm docker.io/openpolicyagent/opa:0.41.0
	OPA_RW := docker run -i -v $(shell pwd):/policies -w /policies --rm docker.io/openpolicyagent/opa:0.41.0
endif

policy.wasm: client_registration.rego register.rego
	$(OPA_RW) build -t wasm -e "client_registration/violation" -e "register/violation" $^
	tar xzf bundle.tar.gz /policy.wasm
	$(RM) bundle.tar.gz
	touch $@

.PHONY: fmt
fmt:
	$(OPA_RW) fmt -w .

.PHONY: test
test:
	$(OPA) test -v ./*.rego

.PHONY: coverage
coverage:
	$(OPA) test --coverage ./*.rego | $(OPA) eval --format pretty \
		--stdin-input \
		--data util/coveralls.rego \
		data.coveralls.from_opa > coverage.json

.PHONY: lint
lint:
	$(OPA) fmt -d --fail .
	$(OPA) check --strict .
