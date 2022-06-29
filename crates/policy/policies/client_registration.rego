package client_registration

import future.keywords.in

default allow := false

allow {
	count(violation) == 0
}

secure_url(x) {
	is_string(x)
	startswith(x, "https://")
}

violation[{"msg": "missing client_uri"}] {
	not input.client_metadata.client_uri
}

violation[{"msg": "invalid client_uri"}] {
	not secure_url(input.client_metadata.client_uri)
}

violation[{"msg": "missing tos_uri"}] {
	not input.client_metadata.tos_uri
}

violation[{"msg": "invalid tos_uri"}] {
	not secure_url(input.client_metadata.tos_uri)
}

violation[{"msg": "missing policy_uri"}] {
	not input.client_metadata.policy_uri
}

violation[{"msg": "invalid policy_uri"}] {
	not secure_url(input.client_metadata.policy_uri)
}

violation[{"msg": "missing redirect_uris"}] {
	not input.client_metadata.redirect_uris
}

violation[{"msg": "invalid redirect_uris"}] {
	not is_array(input.client_metadata.redirect_uris)
}

violation[{"msg": "empty redirect_uris"}] {
	count(input.client_metadata.redirect_uris) == 0
}

violation[{"msg": "invalid redirect_uri"}] {
	# For 'web' apps, we should verify that redirect_uris are secure
	input.client_metadata.application_type != "native"
	some redirect_uri in input.client_metadata.redirect_uris
	not secure_url(redirect_uri)
}

valid_native_redirector(x) {
	is_string(x)
	startswith(x, "http://localhost:")
}

valid_native_redirector(x) {
	is_string(x)
	startswith(x, "http://localhost/")
}

valid_native_redirector(x) {
	is_string(x)
	startswith(x, "http://127.0.0.1")
}

valid_native_redirector(x) {
	is_string(x)
	startswith(x, "http://[::1]")
}

valid_native_redirector(x) {
	is_string(x)
	not startswith(x, "http:")
	not startswith(x, "https:")
	regex.match("^[a-z][a-z0-9+.-]*:", x)
}

violation[{"msg": "invalid redirect_uri"}] {
	# For 'native' apps, we need to check that the redirect_uri is either
	# a custom scheme, or localhost
	# TODO: this might not be right, because of app-associated domains on mobile?
	input.client_metadata.application_type == "native"
	some redirect_uri in input.client_metadata.redirect_uris
	not valid_native_redirector(redirect_uri)
}
