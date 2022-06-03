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
	some redirect_uri in input.client_metadata.redirect_uris
	not secure_url(redirect_uri)
}
