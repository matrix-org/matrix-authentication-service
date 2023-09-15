package client_registration

test_valid {
	allow with input.client_metadata as {
		"grant_types": ["authorization_code"],
		"client_uri": "https://example.com/",
		"redirect_uris": ["https://example.com/callback"],
		"contacts": ["contact@example.com"],
	}
}

test_missing_client_uri {
	not allow with input.client_metadata as {
		"grant_types": [],
		"contacts": ["contact@example.com"],
	}

	allow with input.client_metadata as {
		"grant_types": [],
		"contacts": ["contact@example.com"],
	}
		with data.client_registration.allow_missing_client_uri as true
}

test_insecure_client_uri {
	not allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "http://example.com/",
		"contacts": ["contact@example.com"],
	}
}

test_tos_uri {
	allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"tos_uri": "https://example.com/tos",
		"contacts": ["contact@example.com"],
	}

	# Insecure
	not allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"tos_uri": "http://example.com/tos",
		"contacts": ["contact@example.com"],
	}

	# Insecure, but allowed by the config
	allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"tos_uri": "http://example.com/tos",
		"contacts": ["contact@example.com"],
	}
		with data.client_registration.allow_insecure_uris as true

	# Host mistmatch
	not allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"tos_uri": "https://example.org/tos",
		"contacts": ["contact@example.com"],
	}

	# TOS on a subdomain of the client_uri host is allowed
	allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"tos_uri": "https://tos.example.com/",
		"contacts": ["contact@example.com"],
	}

	# Host mistmatch, but allowed by the config
	allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"tos_uri": "https://example.org/tos",
		"contacts": ["contact@example.com"],
	}
		with data.client_registration.allow_host_mismatch as true
}

test_logo_uri {
	allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"logo_uri": "https://example.com/logo.png",
		"contacts": ["contact@example.com"],
	}

	# Insecure
	not allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"logo_uri": "http://example.com/logo.png",
		"contacts": ["contact@example.com"],
	}

	# Insecure, but allowed by the config
	allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"logo_uri": "http://example.com/logo.png",
		"contacts": ["contact@example.com"],
	}
		with data.client_registration.allow_insecure_uris as true

	# Host mistmatch
	not allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"logo_uri": "https://example.org/logo.png",
		"contacts": ["contact@example.com"],
	}

	# Logo on a subdomain of the client_uri host is allowed
	allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"logo_uri": "https://static.example.com/logo.png",
		"contacts": ["contact@example.com"],
	}

	# Host mistmatch, but allowed by the config
	allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"logo_uri": "https://example.org/logo.png",
		"contacts": ["contact@example.com"],
	}
		with data.client_registration.allow_host_mismatch as true
}

test_policy_uri {
	allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"policy_uri": "https://example.com/policy",
		"contacts": ["contact@example.com"],
	}

	# Insecure
	not allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"policy_uri": "http://example.com/policy",
		"contacts": ["contact@example.com"],
	}

	# Insecure, but allowed by the config
	allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"policy_uri": "http://example.com/policy",
		"contacts": ["contact@example.com"],
	}
		with data.client_registration.allow_insecure_uris as true

	# Host mistmatch
	not allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"policy_uri": "https://example.org/policy",
		"contacts": ["contact@example.com"],
	}

	# Policy on a subdomain of the client_uri host is allowed
	allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"policy_uri": "https://policy.example.com/",
		"contacts": ["contact@example.com"],
	}

	# Host mistmatch, but allowed by the config
	allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"policy_uri": "https://example.org/policy",
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

	# Not required for the client_credentials grant
	allow with input.client_metadata as {
		"grant_types": ["client_credentials"],
		"client_uri": "https://example.com/",
		"contacts": ["contact@example.com"],
	}

	# Required for the authorization_code grant
	not allow with input.client_metadata as {
		"grant_types": ["client_credentials", "refresh_token", "authorization_code"],
		"client_uri": "https://example.com/",
		"contacts": ["contact@example.com"],
	}

	# Required for the implicit grant
	not allow with input.client_metadata as {
		"grant_types": ["client_credentials", "implicit"],
		"client_uri": "https://example.com/",
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

	# Redirect URI on a subdomain of the client_uri host is allowed
	allow with input.client_metadata as {
		"application_type": "web",
		"client_uri": "https://example.com/",
		"redirect_uris": ["https://app.example.com/callback"],
		"contacts": ["contact@example.com"],
	}

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
		"grant_types": [],
		"client_uri": "https://example.com/",
	}

	# Missing contacts, but allowed by config
	allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
	}
		with data.client_registration.allow_missing_contacts as true

	# contacts is not an array
	not allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"contacts": "contact@example.com",
	}

	# Empty contacts
	not allow with input.client_metadata as {
		"grant_types": [],
		"client_uri": "https://example.com/",
		"contacts": [],
	}
}

test_client_credentials_grant {
	# Allowed for confidential clients
	allow with input.client_metadata as {
		"grant_types": ["client_credentials"],
		"token_endpoint_auth_method": "client_secret_basic",
		"client_uri": "https://example.com/",
		"contacts": ["contact@example.com"],
	}
	allow with input.client_metadata as {
		"grant_types": ["client_credentials"],
		# If omitted, defaults to "client_secret_basic"
		"client_uri": "https://example.com/",
		"contacts": ["contact@example.com"],
	}

	# Disallowed for public clients
	not allow with input.client_metadata as {
		"grant_types": ["client_credentials"],
		"token_endpoint_auth_method": "none",
		"client_uri": "https://example.com/",
		"contacts": ["contact@example.com"],
	}
}

test_is_subdomain {
	is_subdomain("example.com", "example.com")
	is_subdomain("example.com", "app.example.com")
	not is_subdomain("example.com", "example.org")
	not is_subdomain("test.com", "example.com")
}

test_reverse_dns_match {
	reverse_dns_match("example.com", "com.example")
	reverse_dns_match("example.com", "com.example.app")
	not reverse_dns_match("example.com", "org.example")
	not reverse_dns_match("test.com", "com.example")
}
