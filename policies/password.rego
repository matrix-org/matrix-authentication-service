# METADATA
# schemas:
# - input: schema["password_input"]
package password

default allow := false

allow {
	count(violation) == 0
}

violation[{"msg": msg}] {
	count(input.password) < data.passwords.min_length
	msg := sprintf("needs to be at least %d characters", [data.passwords.min_length])
}

violation[{"msg": "requires at least one number"}] {
	data.passwords.require_number
	not regex.match("[0-9]", input.password)
}

violation[{"msg": "requires at least one lowercase letter"}] {
	data.passwords.require_lowercase
	not regex.match("[a-z]", input.password)
}

violation[{"msg": "requires at least one uppercase letter"}] {
	data.passwords.require_uppercase
	not regex.match("[A-Z]", input.password)
}
