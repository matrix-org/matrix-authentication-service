# METADATA
# schemas:
#   - input: schema["email_input"]
package email

import future.keywords.in

default allow := false

allow {
	count(violation) == 0
}

# Allow any domains if the data.allowed_domains array is not set
email_domain_allowed {
	not data.allowed_domains
}

# Allow an email only if its domain is in the list of allowed domains
email_domain_allowed {
	[_, domain] := split(input.email, "@")
	some allowed_domain in data.allowed_domains
	glob.match(allowed_domain, ["."], domain)
}

violation[{"msg": "email domain is not allowed"}] {
	not email_domain_allowed
}

# Deny emails with their domain in the domains banlist
violation[{"msg": "email domain is banned"}] {
	[_, domain] := split(input.email, "@")
	some banned_domain in data.banned_domains
	glob.match(banned_domain, ["."], domain)
}
