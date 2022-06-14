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
