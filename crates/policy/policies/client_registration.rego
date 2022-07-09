package client_registration

import future.keywords.in

default allow := false

allow {
	count(violation) == 0
}

parse_uri(url) = obj {
	is_string(url)
	[matches] := regex.find_all_string_submatch_n("^(?P<scheme>[a-z][a-z0-9+.-]*):(?://(?P<host>((?:(?:[a-z0-9]|[a-z0-9][a-z0-9-]*[a-z0-9])\\.)*(?:[a-z0-9]|[a-z0-9][a-z0-9-]*[a-z0-9])|127.0.0.1|0.0.0.0|\\[::1\\])(?::(?P<port>[0-9]+))?))?(?P<path>/[A-Za-z0-9/.-]*)$", url, 1)
	obj := {"scheme": matches[1], "authority": matches[2], "host": matches[3], "port": matches[4], "path": matches[5]}
}

secure_url(x) {
	url := parse_uri(x)
	url.scheme == "https"

	# Disallow localhost variants
	url.host != "localhost"
	url.host != "127.0.0.1"
	url.host != "0.0.0.0"
	url.host != "[::1]"

	# Must be standard port for HTTPS
	url.port == ""
}

host_matches_client_uri(x) {
	client_uri := parse_uri(input.client_metadata.client_uri)
	uri := parse_uri(x)
	uri.host == client_uri.host
}

violation[{"msg": "missing client_uri"}] {
	not input.client_metadata.client_uri
}

violation[{"msg": "invalid client_uri"}] {
	not data.client_registration.allow_insecure_uris
	not secure_url(input.client_metadata.client_uri)
}

violation[{"msg": "invalid tos_uri"}] {
	input.client_metadata.tos_uri
	not data.client_registration.allow_insecure_uris
	not secure_url(input.client_metadata.tos_uri)
}

violation[{"msg": "tos_uri not on the same host as the client_uri"}] {
	input.client_metadata.tos_uri
	not data.client_registration.allow_host_mismatch
	not host_matches_client_uri(input.client_metadata.tos_uri)
}

violation[{"msg": "invalid policy_uri"}] {
	input.client_metadata.policy_uri
	not data.client_registration.allow_insecure_uris
	not secure_url(input.client_metadata.policy_uri)
}

violation[{"msg": "policy_uri not on the same host as the client_uri"}] {
	input.client_metadata.policy_uri
	not data.client_registration.allow_host_mismatch
	not host_matches_client_uri(input.client_metadata.policy_uri)
}

violation[{"msg": "invalid logo_uri"}] {
	input.client_metadata.logo_uri
	not data.client_registration.allow_insecure_uris
	not secure_url(input.client_metadata.logo_uri)
}

violation[{"msg": "logo_uri not on the same host as the client_uri"}] {
	input.client_metadata.logo_uri
	not data.client_registration.allow_host_mismatch
	not host_matches_client_uri(input.client_metadata.logo_uri)
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

violation[{"msg": "invalid redirect_uri", "redirect_uri": redirect_uri}] {
	# For 'web' apps, we should verify that redirect_uris are secure
	input.client_metadata.application_type != "native"
	some redirect_uri in input.client_metadata.redirect_uris
	not data.client_registration.allow_host_mismatch
	not host_matches_client_uri(redirect_uri)
}

violation[{"msg": "invalid redirect_uri"}] {
	# For 'web' apps, we should verify that redirect_uris are secure
	input.client_metadata.application_type != "native"
	some redirect_uri in input.client_metadata.redirect_uris
	not data.client_registration.allow_insecure_uris
	not secure_url(redirect_uri)
}

# Used to verify that a reverse-dns formatted scheme is a strict subdomain of
# another host.
# This is used so a redirect_uri like 'com.example.app:/' works for
# a 'client_uri' of 'https://example.com/'
reverse_dns_match(host, reverse_dns) {
	is_string(host)
	is_string(reverse_dns)

	# Reverse the host
	host_parts := array.reverse(split(host, "."))

	# Split the already reversed DNS
	dns_parts := split(reverse_dns, ".")

	# Check that the reverse_dns strictly is a subdomain of the host
	array.slice(dns_parts, 0, count(host_parts)) == host_parts
}

valid_native_redirector(x) {
	url := parse_uri(x)
	is_localhost(url.host)
	url.scheme == "http"
}

is_localhost(host) {
	host == "localhost"
}

is_localhost(host) {
	host == "127.0.0.1"
}

is_localhost(host) {
	host == "[::1]"
}

# Custom schemes should match the client_uri, reverse-dns style
# e.g. io.element.app:/ matches https://app.element.io/
valid_native_redirector(x) {
	url := parse_uri(x)
	url.scheme != "http"
	url.scheme != "https"

	# They should have no host/port
	url.authority == ""
	client_uri := parse_uri(input.client_metadata.client_uri)
	reverse_dns_match(client_uri.host, url.scheme)
}

violation[{"msg": "invalid redirect_uri"}] {
	# For 'native' apps, we need to check that the redirect_uri is either
	# a custom scheme, or localhost
	# TODO: this might not be right, because of app-associated domains on mobile?
	input.client_metadata.application_type == "native"
	some redirect_uri in input.client_metadata.redirect_uris
	not valid_native_redirector(redirect_uri)
}
