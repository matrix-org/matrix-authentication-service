# Set to 1 to run OPA through Docker
DOCKER := 0
PODMAN := 0
OPA_DOCKER_IMAGE := docker.io/openpolicyagent/opa:0.64.1-debug

INPUTS := \
	client_registration.rego \
	register.rego \
	authorization_grant.rego \
	password.rego \
	email.rego

ifeq ($(DOCKER), 1)
	OPA := docker run -i -v $(shell pwd):/policies:ro -w /policies --rm $(OPA_DOCKER_IMAGE)
	OPA_RW := docker run -i -v $(shell pwd):/policies -w /policies --rm $(OPA_DOCKER_IMAGE)
else ifeq ($(PODMAN), 1)
	# When running rootless, the volume directory may need to be given global write permissions on the host
	OPA := podman run -i -v $(shell pwd):/policies:ro:Z -w /policies --rm $(OPA_DOCKER_IMAGE)
	OPA_RW := podman run -i -v $(shell pwd):/policies:Z -w /policies --rm $(OPA_DOCKER_IMAGE)
else
	OPA := opa
	OPA_RW := opa
endif

policy.wasm: $(INPUTS)
	$(OPA_RW) build -t wasm \
		-e "client_registration/violation" \
		-e "register/violation" \
		-e "authorization_grant/violation" \
		-e "password/violation" \
		-e "email/violation" \
		$^
	tar xzf bundle.tar.gz /policy.wasm
	$(RM) bundle.tar.gz
	touch $@

.PHONY: fmt
fmt:
	$(OPA_RW) fmt -w .

.PHONY: test
test:
	$(OPA) test --schema ./schema/ -v ./*.rego

.PHONY: coverage
coverage:
	$(OPA) test --coverage ./*.rego | $(OPA) eval --format pretty \
		--stdin-input \
		--data util/coveralls.rego \
		data.coveralls.from_opa > coverage.json

.PHONY: lint
lint:
	$(OPA) fmt -d --fail ./*.rego util/*.rego
	$(OPA) check --strict --schema schema/ ./*.rego util/*.rego
