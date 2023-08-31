package client_registration

test_valid {
	allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"redirect_uris": ["https://example.com/callback"],
		"contacts": ["contact@example.com"],
	}
}

test_missing_client_uri {
	not allow with input.client_metadata as {
		"redirect_uris": ["https://example.com/callback"],
		"contacts": ["contact@example.com"],
	}

	allow with input.client_metadata as {
		"redirect_uris": ["https://example.com/callback"],
		"contacts": ["contact@example.com"],
	}
		with data.client_registration.allow_missing_client_uri as true
}

test_insecure_client_uri {
	not allow with input.client_metadata as {
		"client_uri": "http://example.com/",
		"redirect_uris": ["https://example.com/callback"],
		"contacts": ["contact@example.com"],
	}
}

test_tos_uri {
	allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"tos_uri": "https://example.com/tos",
		"redirect_uris": ["https://example.com/callback"],
		"contacts": ["contact@example.com"],
	}

	# Insecure
	not allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"tos_uri": "http://example.com/tos",
		"redirect_uris": ["https://example.com/callback"],
		"contacts": ["contact@example.com"],
	}

	# Insecure, but allowed by the config
	allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"tos_uri": "http://example.com/tos",
		"redirect_uris": ["https://example.com/callback"],
		"contacts": ["contact@example.com"],
	}
		with data.client_registration.allow_insecure_uris as true

	# Host mistmatch
	not allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"tos_uri": "https://example.org/tos",
		"redirect_uris": ["https://example.com/callback"],
		"contacts": ["contact@example.com"],
	}

	# Host mistmatch, but allowed by the config
	allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"tos_uri": "https://example.org/tos",
		"redirect_uris": ["https://example.com/callback"],
		"contacts": ["contact@example.com"],
	}
		with data.client_registration.allow_host_mismatch as true
}

test_logo_uri {
	allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"logo_uri": "https://example.com/logo.png",
		"redirect_uris": ["https://example.com/callback"],
		"contacts": ["contact@example.com"],
	}

	# Insecure
	not allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"logo_uri": "http://example.com/logo.png",
		"redirect_uris": ["https://example.com/callback"],
		"contacts": ["contact@example.com"],
	}

	# Insecure, but allowed by the config
	allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"logo_uri": "http://example.com/logo.png",
		"redirect_uris": ["https://example.com/callback"],
		"contacts": ["contact@example.com"],
	}
		with data.client_registration.allow_insecure_uris as true

	# Host mistmatch
	not allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"logo_uri": "https://example.org/logo.png",
		"redirect_uris": ["https://example.com/callback"],
		"contacts": ["contact@example.com"],
	}

	# Host mistmatch, but allowed by the config
	allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"logo_uri": "https://example.org/logo.png",
		"redirect_uris": ["https://example.com/callback"],
		"contacts": ["contact@example.com"],
	}
		with data.client_registration.allow_host_mismatch as true
}

test_policy_uri {
	allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"policy_uri": "https://example.com/policy",
		"redirect_uris": ["https://example.com/callback"],
		"contacts": ["contact@example.com"],
	}

	# Insecure
	not allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"policy_uri": "http://example.com/policy",
		"redirect_uris": ["https://example.com/callback"],
		"contacts": ["contact@example.com"],
	}

	# Insecure, but allowed by the config
	allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"policy_uri": "http://example.com/policy",
		"redirect_uris": ["https://example.com/callback"],
		"contacts": ["contact@example.com"],
	}
		with data.client_registration.allow_insecure_uris as true

	# Host mistmatch
	not allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"policy_uri": "https://example.org/policy",
		"redirect_uris": ["https://example.com/callback"],
		"contacts": ["contact@example.com"],
	}

	# Host mistmatch, but allowed by the config
	allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"policy_uri": "https://example.org/policy",
		"redirect_uris": ["https://example.com/callback"],
		"contacts": ["contact@example.com"],
	}
		with data.client_registration.allow_host_mismatch as true
}

test_redirect_uris {
	# Missing redirect_uris
	not allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"contacts": ["contact@example.com"],
	}

	# redirect_uris is not an array
	not allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"redirect_uris": "https://example.com/callback",
		"contacts": ["contact@example.com"],
	}

	# Empty redirect_uris
	not allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"redirect_uris": [],
		"contacts": ["contact@example.com"],
	}
}

test_web_redirect_uri {
	allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com/",
		"redirect_uris": ["https://example.com/second/callback", "https://example.com/callback"],
		"contacts": ["contact@example.com"],
	}

	# Insecure URL
	not allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com/",
		"redirect_uris": ["http://example.com/callback", "https://example.com/callback"],
		"contacts": ["contact@example.com"],
	}

	# Insecure URL, but allowed by the config
	allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com/",
		"redirect_uris": ["http://example.com/callback", "https://example.com/callback"],
		"contacts": ["contact@example.com"],
	}
		with data.client_registration.allow_insecure_uris as true

	# Host mismatch
	not allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com/",
		"redirect_uris": ["https://example.com/second/callback", "https://example.org/callback"],
		"contacts": ["contact@example.com"],
	}

	# Host mismatch, but allowed by the config
	allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com/",
		"redirect_uris": ["https://example.com/second/callback", "https://example.org/callback"],
		"contacts": ["contact@example.com"],
	}
		with data.client_registration.allow_host_mismatch as true

	# No custom scheme allowed
	not allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com/",
		"redirect_uris": ["com.example.app:/callback"],
		"contacts": ["contact@example.com"],
	}

	# localhost not allowed
	not allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com/",
		"redirect_uris": ["http://locahost:1234/callback"],
		"contacts": ["contact@example.com"],
	}

	# localhost not allowed
	not allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com/",
		"redirect_uris": ["http://127.0.0.1:1234/callback"],
		"contacts": ["contact@example.com"],
	}

	# localhost not allowed
	not allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com/",
		"redirect_uris": ["http://[::1]:1234/callback"],
		"contacts": ["contact@example.com"],
	}
}

test_native_redirect_uri {
	# This has all the redirect URIs types we're supporting for native apps
	allow with input.client_metadata as {
		"application_type": "native",
		"client_uri": "https://example.com/",
		"redirect_uris": [
			"com.example.app:/callback",
			"http://localhost/callback",
			"http://localhost:1234/callback",
			"http://127.0.0.1/callback",
			"http://127.0.0.1:1234/callback",
			"http://[::1]/callback",
			"http://[::1]:1234/callback",
		],
		"contacts": ["contact@example.com"],
	}

	# We still allow matching URLs for native apps
	allow with input.client_metadata as {
		"application_type": "native",
		"client_uri": "https://example.com/",
		"redirect_uris": ["https://example.com/"],
		"contacts": ["contact@example.com"],
	}

	# But not insecure
	not allow with input.client_metadata as {
		"application_type": "native",
		"client_uri": "https://example.com/",
		"redirect_uris": ["http://example.com/"],
		"contacts": ["contact@example.com"],
	}

	# And not a mismatch
	not allow with input.client_metadata as {
		"application_type": "native",
		"client_uri": "https://example.com/",
		"redirect_uris": ["http://bad.com/"],
		"contacts": ["contact@example.com"],
	}

	# We don't allow HTTPS on localhost
	not allow with input.client_metadata as {
		"application_type": "native",
		"client_uri": "https://example.com/",
		"redirect_uris": ["https://localhost:1234/"],
		"contacts": ["contact@example.com"],
	}

	# Ensure we're not allowing localhost as a prefix
	not allow with input.client_metadata as {
		"application_type": "native",
		"client_uri": "https://example.com/",
		"redirect_uris": ["http://localhost.com/"],
		"contacts": ["contact@example.com"],
	}

	# For custom schemes, it should match the client_uri hostname
	not allow with input.client_metadata as {
		"application_type": "native",
		"client_uri": "https://example.com/",
		"redirect_uris": ["org.example.app:/callback"],
		"contacts": ["contact@example.com"],
	}
}

test_reverse_dns_match {
	client_uri := parse_uri("https://element.io/")
	redirect_uri := parse_uri("io.element.app:/callback")
	reverse_dns_match(client_uri.host, redirect_uri.scheme)
}

test_contacts {
	# Missing contacts
	not allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"redirect_uris": ["https://example.com/callback"],
	}

	# Missing contacts, but allowed by config
	allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"redirect_uris": ["https://example.com/callback"],
	}
		with data.client_registration.allow_missing_contacts as true

	# contacts is not an array
	not allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"redirect_uris": ["https://example.com/callback"],
		"contacts": "contact@example.com",
	}

	# Empty contacts
	not allow with input.client_metadata as {
		"client_uri": "https://example.com/",
		"redirect_uris": ["https://example.com/callback"],
		"contacts": [],
	}
}
