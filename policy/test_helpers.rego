package test.helpers
import rego.v1

empty(value) if {
	count(value) == 0
}

no_violations(value) if {
	empty(value)
}
