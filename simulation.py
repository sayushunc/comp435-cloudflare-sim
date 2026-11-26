import json,csv,sys

# usage: python3 simulation.py 3 show3 simulation.py [token_lifetime] [show]
# token_lifetime = how many steps a session token lives (default 3)
# show = also print the table in the terminal
ttl = 3
if len(sys.argv) > 1:
    ttl = int(sys.argv[1])
show = "show" in sys.argv

# how many steps after disabling the stolen account we check access
delay = 2

class Sim:
    def __init__(self,cascade=False,least_priv=False,revoke=False,ttl=3):
        with open("sample_data.json","r") as f:
            data = json.load(f)

        self.cascade = cascade
        self.least_priv = least_priv
        self.revoke = revoke
        self.users = {}
        self.docs = data["sample_documents"]

        # session tokens: the clock moves forward in steps and a token lives for ttl steps
        self.time = 0
        self.ttl = ttl
        self.sessions = []

        # set up initial accounts from json
        for uname,info in data["initial_accounts"].items():
            perms = list(info["permissions"])
            if self.least_priv and "create_account" in perms:
                perms.remove("create_account")

            self.users[uname] = {
                "role": info["role"],
                "active": info["active"],
                "created_by": info["created_by"],
                "perms": perms
            }

    # attacker logs in and gets a session token that lasts ttl steps
    def login(self,uname):
        if uname not in self.users or not self.users[uname]["active"]:
            return
        self.sessions.append({"user":uname,"expires":self.time + self.ttl})

    # move the clock forward
    def wait(self,steps):
        self.time += steps

    # does this user still have a token that hasn't expired
    def has_session(self,uname):
        for s in self.sessions:
            if s["user"] == uname and s["expires"] > self.time:
                return True
        return False

    # attacker tries to make a second account for persistence
    def make_account(self,actor,new_user):
        if actor not in self.users:
            return
        u = self.users[actor]
        if not u["active"] or "create_account" not in u["perms"]:
            return

        self.users[new_user] = {
            "role": "rogue_persistence",
            "active": True,
            "created_by": actor,
            "perms": ["read_jira","read_confluence","read_bitbucket"]
        }

    # disable an account (and child accounts if cascading is on)
    def disable(self,target):
        if target not in self.users:
            return
        self.users[target]["active"] = False
        killed = [target]

        if self.cascade:
            for uname,info in self.users.items():
                if info["created_by"] == target and info["active"]:
                    info["active"] = False
                    killed.append(uname)

        # if revoke is on, disabling also kills the open session tokens
        if self.revoke:
            self.sessions = [s for s in self.sessions if s["user"] not in killed]

    # check if a user can access a specific system
    def check(self,uname,sys_name):
        if uname not in self.users:
            return "DENIED (Not Created)"

        u = self.users[uname]
        by_token = False
        if not u["active"]:
            # account is disabled but a token that hasn't expired still works
            if not self.has_session(uname):
                return "DENIED (Account Disabled)"
            by_token = True

        doc = None
        for d in self.docs:
            if d["system"] == sys_name:
                doc = d
                break

        if doc["trust_zone"] == "zero_trust_production":
            return "BLOCKED (Network Boundary)"

        if doc["required_permission"] in u["perms"]:
            if by_token:
                return "ALLOWED (Session Token)"
            return "ALLOWED"

        return "DENIED (Missing Perm)"


# list of scenarios to test (name,mode,cascade,least_priv,revoke)
# 1-5 don't use session tokens, so a disabled account is blocked right away
# 6-11 give the attacker a session token that lasts ttl steps
scenarios = [
    ("1. Disable Stolen Cred BEFORE Entry","before",False,False,False),
    ("2. Disable Stolen Cred AFTER Entry (Naive)","after_naive",False,False,False),
    ("3. Disable AFTER + Manual 2nd Acct Cleanup","after_manual",False,False,False),
    ("4. Disable AFTER + Cascading Revocation","after_cascade",True,False,False),
    ("5. Enforce Least Privilege on Service Acct","after_least_priv",False,True,False),
    ("6. Disable AFTER, Checked Soon After (Naive)","token_now",False,False,False),
    ("7. Disable AFTER, Checked After Token Expires (Naive)","token_later",False,False,False),
    ("8. Revoke Sessions Only, Checked Soon After","token_now",False,False,True),
    ("9. Least Privilege Only, Checked Soon After","token_now",False,True,False),
    ("10. Cascading Only, Checked Soon After","token_now",True,False,False),
    ("11. Cascading + Revoke Sessions, Checked Soon After","token_now",True,False,True)
]

rows = [["Scenario","Account Tested","Jira Docs","Confluence Wiki","Bitbucket Code","Prod Network"]]

for name,mode,cascade,least_priv,revoke in scenarios:
    s = Sim(cascade,least_priv,revoke,ttl)

    # run the scenario steps based on timing
    if mode == "before":
        s.disable("okta_svc_admin")
        s.make_account("okta_svc_admin","rogue_acct_2")
    elif mode in ("after_naive","after_cascade","after_least_priv"):
        s.make_account("okta_svc_admin","rogue_acct_2")
        s.disable("okta_svc_admin")
    elif mode == "after_manual":
        s.make_account("okta_svc_admin","rogue_acct_2")
        s.disable("okta_svc_admin")
        s.disable("rogue_acct_2")
    elif mode in ("token_now","token_later"):
        # attacker logs in first so they have a token, then the stolen account gets disabled
        s.login("okta_svc_admin")
        s.make_account("okta_svc_admin","rogue_acct_2")
        s.disable("okta_svc_admin")
        if mode == "token_now":
            s.wait(delay)
        else:
            s.wait(s.ttl + 1)

    # record results for both accounts
    for acc in ["okta_svc_admin","rogue_acct_2"]:
        jira = s.check(acc,"Jira")
        conf = s.check(acc,"Confluence")
        bitb = s.check(acc,"Bitbucket")
        prod = s.check(acc,"Production_Network")
        rows.append([name,acc,jira,conf,bitb,prod])

# save results to access_results.csv file
with open("access_results.csv","w",newline="") as f:
    writer = csv.writer(f)
    writer.writerows(rows)

# print the table if show was passed
if show:
    print("token lifetime =",ttl,"steps, checked",delay,"steps after disabling")
    for r in rows:
        print(r[0].ljust(54),r[1].ljust(15),r[2].ljust(24),r[3].ljust(24),r[4].ljust(24),r[5])
