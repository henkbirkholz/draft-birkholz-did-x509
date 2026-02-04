validate_predicate(name, value) := true if {
    name == "eku"
    value == input.chain[0].extensions.eku[_]
}
