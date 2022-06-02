package register

import future.keywords.in

default allow := false
allow := true {
	count(violation) == 0
}

violation[{"field": "username", "msg": "username too short"}] {
	count(input.user.username) <= 2
}

violation[{"field": "username", "msg": "username too long"}] {
	count(input.user.username) >= 15 
}

# Allow any domains if the data.allowed_domains array is not set
email_domain_allowed {
	not data.allowed_domains
}

# Allow an email only if its domain is in the list of allowed domains
email_domain_allowed {
	[_, domain] := split(input.user.email, "@")
	some allowed_domain in data.allowed_domains
	glob.match(allowed_domain, ["."], domain)
}

violation[{"field": "email", "msg": "email domain not allowed"}] {
	not email_domain_allowed
}

# Deny emails with their domain in the domains banlist
violation[{"field": "email", "msg": "email domain not allowed"}] {
	[_, domain] := split(input.user.email, "@")
	some banned_domain in data.banned_domains
	glob.match(banned_domain, ["."], domain)
}


