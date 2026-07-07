#! VULNERABLE env-var-gate — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant setEnv

let raw = fetch<web>
privileged { setEnv(raw) }  # tainted -> tool: REJECTED
