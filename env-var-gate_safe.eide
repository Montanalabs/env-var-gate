#! Env-var gate — untrusted a request can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires setEnv — the env-var gate sink
#! @effect io
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant setEnv

type EnvVar = RegionVar | TierVar | FlagVar
type Decision = SetVar(EnvVar) | RejectVar

let raw = fetch<web>  # UNTRUSTED a request — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
privileged { setEnv(d) }  # act on the trusted decision only
