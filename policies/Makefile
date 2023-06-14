# Set to 1 to run OPA through Docker
DOCKER := 0
OPA_DOCKER_IMAGE := docker.io/openpolicyagent/opa:0.53.1

ifeq ($(DOCKER), 0)
	OPA := opa
	OPA_RW := opa
else
	OPA := docker run -i -v $(shell pwd):/policies:ro -w /policies --rm $(OPA_DOCKER_IMAGE)
	OPA_RW := docker run -i -v $(shell pwd):/policies -w /policies --rm $(OPA_DOCKER_IMAGE)
endif

policy.wasm: client_registration.rego register.rego authorization_grant.rego
	$(OPA_RW) build -t wasm \
		-e "client_registration/violation" \
		-e "register/violation" \
		-e "authorization_grant/violation" \
		$^
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
