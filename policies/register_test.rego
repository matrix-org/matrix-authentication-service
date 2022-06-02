package register

mock_user := {"username": "hello", "email": "hello@staging.element.io"}

test_allow_all_domains {
	allow with input.user as mock_user
}

test_allowed_domain {
	allow 
		with input.user as mock_user
		with data.allowed_domains as ["*.element.io"]
}

test_not_allowed_domain {
	not allow 
		with input.user as mock_user
		with data.allowed_domains as ["example.com"]
}

test_banned_domain {
	not allow 
		with input.user as mock_user
		with data.banned_domains as ["*.element.io"]
}

test_banned_subdomain {
	not allow 
		with input.user as mock_user
		with data.allowed_domains as ["*.element.io"]
		with data.banned_domains as ["staging.element.io"]
}
