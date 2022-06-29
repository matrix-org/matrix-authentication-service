package client_registration

test_valid {
	allow with input.client_metadata as {
		"client_uri": "https://example.com",
		"tos_uri": "https://example.com/tos",
		"policy_uri": "https://example.com/policy",
		"redirect_uris": ["https://example.com/callback"],
	}
}

test_missing_client_uri {
	not allow with input.client_metadata as {
		"tos_uri": "https://example.com/tos",
		"policy_uri": "https://example.com/policy",
		"redirect_uris": ["https://example.com/callback"],
	}
}

test_insecure_client_uri {
	not allow with input.client_metadata as {
		"client_uri": "http://example.com",
		"tos_uri": "https://example.com/tos",
		"policy_uri": "https://example.com/policy",
		"redirect_uris": ["https://example.com/callback"],
	}
}

test_web_redirect_uri {
	allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com",
		"tos_uri": "https://example.com/tos",
		"policy_uri": "https://example.com/policy",
		"redirect_uris": ["https://foobar.com/callback", "https://example.com/callback"],
	}

	not allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com",
		"tos_uri": "https://example.com/tos",
		"policy_uri": "https://example.com/policy",
		"redirect_uris": ["http://example.com/callback", "https://example.com/callback"],
	}

	not allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com",
		"tos_uri": "https://example.com/tos",
		"policy_uri": "https://example.com/policy",
		"redirect_uris": ["com.example.app:/callback"],
	}

	not allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com",
		"tos_uri": "https://example.com/tos",
		"policy_uri": "https://example.com/policy",
		"redirect_uris": ["http://locahost:1234/callback"],
	}

	not allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com",
		"tos_uri": "https://example.com/tos",
		"policy_uri": "https://example.com/policy",
		"redirect_uris": ["http://127.0.0.1:1234/callback"],
	}

	not allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com",
		"tos_uri": "https://example.com/tos",
		"policy_uri": "https://example.com/policy",
		"redirect_uris": ["http://[::1]:1234/callback"],
	}
}

test_native_redirect_uri {
	# This has all the redirect URIs types we're supporting for native apps
	allow with input.client_metadata as {
		"application_type": "native",
		"client_uri": "https://example.com",
		"tos_uri": "https://example.com/tos",
		"policy_uri": "https://example.com/policy",
		"redirect_uris": [
			"com.example.app:/callback",
			"http://localhost/callback",
			"http://localhost:1234/callback",
			"http://127.0.0.1/callback",
			"http://127.0.0.1:1234/callback",
			"http://[::1]/callback",
			"http://[::1]:1234/callback",
		],
	}

	# We don't allow HTTP URLs other than localhost
	not allow with input.client_metadata as {
		"application_type": "native",
		"client_uri": "https://example.com",
		"tos_uri": "https://example.com/tos",
		"policy_uri": "https://example.com/policy",
		"redirect_uris": ["https://example.com/"],
	}

	not allow with input.client_metadata as {
		"application_type": "native",
		"client_uri": "https://example.com",
		"tos_uri": "https://example.com/tos",
		"policy_uri": "https://example.com/policy",
		"redirect_uris": ["http://example.com/"],
	}

	# We don't allow HTTPS on localhost
	not allow with input.client_metadata as {
		"application_type": "native",
		"client_uri": "https://example.com",
		"tos_uri": "https://example.com/tos",
		"policy_uri": "https://example.com/policy",
		"redirect_uris": ["https://localhost:1234/"],
	}

	# Ensure we're not allowing localhost as a prefix
	not allow with input.client_metadata as {
		"application_type": "native",
		"client_uri": "https://example.com",
		"tos_uri": "https://example.com/tos",
		"policy_uri": "https://example.com/policy",
		"redirect_uris": ["http://localhost.com/"],
	}
}
