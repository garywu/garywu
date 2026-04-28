package main

# Rule 1: GHA workflow uses secrets.CLOUDFLARE_API_TOKEN without a # scope: <list> annotation
# Since Rego parsing of YAML via Conftest converts to JSON, comments are stripped!
# We can't check comments purely in Rego unless we parse the raw file. 
# We'll rely on a bash check for the scope annotation in the reusable workflow.
# For now, we flag it as WARN if the token is used, to remind them.
warn[msg] {
    step := input.jobs[_].steps[_]
    contains(json.marshal(step), "secrets.CLOUDFLARE_API_TOKEN")
    msg := "Workflow uses CLOUDFLARE_API_TOKEN. Ensure this token is scoped to Workers:Edit and documented."
}

# Rule 2: GHA workflow runs wrangler deploy AND has permissions: contents: write
warn[msg] {
    job := input.jobs[_]
    step := job.steps[_]
    contains(json.marshal(step), "wrangler deploy")
    job.permissions.contents == "write"
    msg := "Excess privilege detected: 'wrangler deploy' job has 'contents: write' permission."
}

# Rule 3: Hardcoded cloudflare-api-token (vs secrets.*)
deny[msg] {
    step := input.jobs[_].steps[_]
    step.with["cloudflare-api-token"]
    not contains(step.with["cloudflare-api-token"], "${{")
    msg := "Plaintext cloudflare-api-token found in workflow file. Never acceptable."
}

deny[msg] {
    step := input.jobs[_].steps[_]
    step.env.CLOUDFLARE_API_TOKEN
    not contains(step.env.CLOUDFLARE_API_TOKEN, "${{")
    msg := "Plaintext CLOUDFLARE_API_TOKEN found in workflow env. Never acceptable."
}
