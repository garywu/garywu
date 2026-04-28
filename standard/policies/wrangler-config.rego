package main

# Heuristic for Backend:
# No "assets" binding, no "site" binding, and name doesn't end with -frontend|-pages|-web|-app
is_backend {
    not input.assets
    not input.site
    not re_match(".*-(frontend|pages|web|app)$", input.name)
    input.name != "api-mom"
}

# Rule 1: JSONC is mandatory, TOML is forbidden (Checked by bash wrapper, but we can't check file extension purely in standard rego without input filename injected. We'll handle this in the bash script or assume input is JSON representation of the config). 
# Actually, Conftest passes the filename if configured, but let's rely on the GHA workflow for extension checking.

# Rule 2: workers_dev: true is forbidden for backends
deny[msg] {
    is_backend
    input.workers_dev == true
    msg := sprintf("Backend worker '%v' MUST NOT set workers_dev to true. (RFC-035 §1)", [input.name])
}

# Rule 3: workers_dev must be explicitly set (if it's missing, it defaults to true)
deny[msg] {
    is_backend
    not has_key(input, "workers_dev")
    msg := sprintf("Backend worker '%v' is missing 'workers_dev' field. It must be explicitly set to false. (RFC-035 §1)", [input.name])
}

# Rule 4: Backend wrangler missing compatibility_date
warn[msg] {
    is_backend
    not input.compatibility_date
    msg := sprintf("Backend worker '%v' is missing 'compatibility_date' for reproducible builds.", [input.name])
}

# Rule 5: *.workers.dev route declared explicitly while workers_dev: false
deny[msg] {
    input.workers_dev == false
    route := input.routes[_]
    is_string(route)
    contains(route, ".workers.dev")
    msg := sprintf("Worker '%v' declares workers_dev: false but explicitly binds a *.workers.dev route.", [input.name])
}

deny[msg] {
    input.workers_dev == false
    route := input.routes[_]
    is_object(route)
    contains(route.pattern, ".workers.dev")
    msg := sprintf("Worker '%v' declares workers_dev: false but explicitly binds a *.workers.dev route pattern.", [input.name])
}

# Helper
has_key(obj, k) {
    _ = obj[k]
}
