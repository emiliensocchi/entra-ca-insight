# 🧱 Opinionated design

This page summarizes the **design** choices selected for CA Insight.


## Definition of Strong Controls

CA Insight aims at identifying scenarios under which an identity can access resources using only **username and password**, without additional security verification. 

Therefore, CA Insight considers that an access scenario is covered **only** if it is terminated by one of the following **strong controls**:

| Control Type | Control name |  Description |
|---|---|---|
| Grant | 🔑 Autentication Strength | Require specific authentication methods for access, such as phishing-resistant MFA. |
| Grant | 📱 Multi-Factor Autentication | Require MFA for access. |
| Block | 🚫 Block | Block access. | 

This means that other controls such as **device compliance** requirements are **not considered enough** if they are enforced alone, as the goal of CA Insight is to find gaps where identity-based verification (MFA/Auth Strength) does **not** apply as the primary security boundary. 


## Identity-Centric approach

CA Insight's **identity-centric** approach represents a fundamental shift from previous offline gap analysis attempts.

**❌ Traditional Group/Role-Centric Approach:**

```
Policy Analysis Finds:
└─ "Finance Team" group: NOT covered by MFA policy ⚠️ GAP ALERT

Investigation Shows:
└─ "Finance Team" has 50 members
    └─ Member: Alice Johnson
        └─ Also in: "Executives" (HAS MFA coverage) ✅
        └─ Also in: "All Users" (HAS MFA coverage) ✅
        └─ Result: Alice is ACTUALLY PROTECTED

False Positive: 49 more users similarly protected via other groups
```

**✅ CA Insight Identity-Centric Approach:**

```
Policy Analysis Process:
1. Flatten all policies  resolve groups/roles to member user IDs
2. For each user, aggregate ALL group/role memberships
3. Evaluate policies against user's complete identity profile

User: Alice Johnson
├─ Member of: Finance Team, Executives, All Users
├─ Policies Covering Alice:
│   ├─ Policy A: All Users → MFA Required ✅
│   └─ Policy B: Executives → Compliant Device Required ✅
└─ Result: Alice is PROTECTED (no gap)

Accurate: No false positives from partial group analysis
```

### Policy Flattening & Resolution

To achieve identity-centric analysis, CA Insight **flattens policies** by resolving all group and role references to their member user IDs:

**Step 1: Flatten Groups**
```
Original Policy:
└─ Include Groups: ["Finance Team", "Sales Team"]
└─ Exclude Groups: ["Contractors"]

Flattened Policy:
└─ Include Users: [user1, user2, user3, ..., user50] (from Finance + Sales)
└─ Exclude Users: [user10, user15] (from Contractors)
└─ Groups removed from policy
```

**Step 2: Flatten Roles (with PIM Support)**
```
Original Policy:
└─ Include Roles: ["Global Administrator"]

Resolution Process:
├─ Permanent assignments: [admin1, admin2]
├─ Eligible assignments (PIM): [admin3 (eligible), admin4 (eligible)]
└─ Group-based role assignments: 
    └─ "IT Admins" group  assigned "Global Admin" role
        └─ Members: [admin5, admin6]
        └─ Eligible members: [admin7 (eligible)]

Flattened Policy:
└─ Include Users: [admin1, admin2, admin3, admin4, admin5, admin6, admin7]
└─ Roles removed from policy
```

**Step 3: Recursive Group Membership**
```
Group Structure:
└─ "Finance Team"
    ├─ Direct members: [user1, user2]  
    └─ Contains nested group: "Finance Managers"
        ├─ Direct members: [user3, user4]
        └─ Contains nested group: "Finance Directors"
            └─ Direct members: [user5]

Resolved Users: [user1, user2, user3, user4, user5]
```

**Result:** Policies stored in `cache/flat_policies-users.json` contain only user IDs, enabling accurate per-identity evaluation without group overlap ambiguity.

## Universal Policy Detection

CA Insight defines policies as **universal** when they cover all possible scenarios for the included identities. For example: 

| Universal Policy Type | Criteria | Impact |
|----------------------|----------|--------|
| Universal MFA/Auth Strength | Targets All apps + MFA/auth strength grant + no other conditions | Users included in the policy are required to have MFA to access any app - They are pre-protected and excluded from permutation testing |
| Universal Block | Targets All apps + Block grant + no other conditions | Users included in the policy are fully blocked when accessing any app - They are pre-protected and excluded from permutation testing |

**Optimization:** Universal policies are evaluated first, and covered identities are removed from the "potentially unprotected" set before permutation generation, dramatically reducing analysis time.
