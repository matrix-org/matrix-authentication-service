package email

test_allow_all_domains {
	allow with input.email as "hello@staging.element.io"
}

test_allowed_domain {
	allow with input.email as "hello@staging.element.io"
		with data.allowed_domains as ["*.element.io"]
}

test_not_allowed_domain {
	not allow with input.email as "hello@staging.element.io"
		with data.allowed_domains as ["example.com"]
}

test_banned_domain {
	not allow with input.email as "hello@staging.element.io"
		with data.banned_domains as ["*.element.io"]
}

test_banned_subdomain {
	not allow with input.email as "hello@staging.element.io"
		with data.allowed_domains as ["*.element.io"]
		with data.banned_domains as ["staging.element.io"]
}
