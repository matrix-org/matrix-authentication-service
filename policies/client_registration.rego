package client_registration

import future.keywords.in

secure_url(x) {
	is_string(x)
	startswith(x, "https://")
}

default allow := false

allow {
	secure_url(input.client_metadata.client_uri)
	secure_url(input.client_metadata.tos_uri)
	secure_url(input.client_metadata.policy_uri)
	some redirect_uri in input.client_metadata.redirect_uris
	secure_url(redirect_uri)
}
