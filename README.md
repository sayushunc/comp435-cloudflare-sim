# Cloudflare 2023 Breach Access Simulation (COMP 435)

Small Python simulation of the stolen-credential attack on Cloudflare's Atlassian systems (Jira, Confluence, Bitbucket) and what happens when different defenses are used.

## Files
- simulation.py - runs all 11 scenarios and writes access_results.csv
- sample_data.json - the fake accounts, systems, and permissions the simulation reads
- access_results.csv - the results table (2 rows per scenario: okta_svc_admin and rogue_acct_2)

## How to run
Needs Python 3 only, no installs. Run it in the same folder as sample_data.json.

    python3 simulation.py            # writes access_results.csv, prints nothing
    python3 simulation.py 3 show     # token lifetime 3, also prints the table
    python3 simulation.py 2 show     # token lifetime 2, compare the difference

The first number is how many steps a session token lives (default 3). Access is checked 2 steps after the stolen account is disabled (the delay value at the top of simulation.py).

## Scenarios
1-5 do not use session tokens, so disabling an account blocks it right away.
1. Disable the stolen credential before the attacker enters
2. Disable it after the attacker made a second account (naive)
3. Same as 2, then also disable the second account by hand
4. Same as 2 with cascading revocation (disabling an account also disables accounts it created)
5. Same as 2 with least privilege (the service account can't create accounts)

6-11 give the attacker a session token.
6. Disable after entry, checked soon after (naive)
7. Same as 6, checked after the token expires
8. Revoke sessions only (disabling an account also kills its tokens)
9. Least privilege only
10. Cascading revocation only
11. Cascading revocation + revoke sessions

## Reading the table
- ALLOWED (Session Token) means the account is disabled but its token still works
- DENIED (Not Created) means the attacker never got to create that account
- BLOCKED (Network Boundary) means the production network zone stopped access. This is an assumption built into the code (based on Cloudflare's report), not something the simulation figures out.

## Limits
- Token lifetime and the check delay are made-up numbers
- Only the stolen account gets a session token
- It models account access only, not Cloudflare's real systems or the malware
