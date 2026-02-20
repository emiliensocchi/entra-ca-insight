
# 🔎 Coverage and Limitations

This page summarizes the **coverage and limitations** of CA Insight.

## Supported Identities

**Note**: those are referred to as "Assignments" in the Entra portal.

| Identity type | Description |
|---|---|
| 🤖 Agent Identities | Service principals of type [`microsoft.graph.agentIdentity`](https://learn.microsoft.com/en-us/graph/api/resources/agentidentity?view=graph-rest-beta). |
| 💼 Guests and Exernal Users | Local guest accounts, B2B collaboration guest users, B2B collaboration members ([more info](https://docs.azure.cn/en-us/entra/external-id/user-properties)). |
| 👤 Member Users | Individual users, security groups, M365 groups, dynamic groups, Entra roles. | 
| 🚀 Workload Identities | Single-tenant service principals registered in the analyzed tenant, that are neither Managed nor Agent Identities. | 
---

## Supported Target Resources

| Resource Type | Description |
|---|---|
| 🤖 Agent Resources | Agent identity blueprint principals and agent identities. |
| 📱 Cloud Applications | Microsoft 365 applications, Admin portals and custom Enterprise applications. |
| 👆 User Actions | Security registration and device join flows. |
---

## Supported Conditions

| Condition | Evaluated? | Justification |
|-----------|----------------|-----------|
| Authentication Flows | ✅ | No simple bypass, evaluate all possible values of that condition. |
| Client App Types | ✅ | No simple bypass, evaluate all possible values of that condition. |
| Locations | ✅ | No simple bypass, evaluate all possible values of that condition. |
| Device Platforms | ❌ | Can be bypassed (only a User-Agent), ignore that condition. |
| Filter for Devices | ❌ | No simple bypass but should not replace identity-based verification such as MFA, ignore that condition for the time being. |
| Insider Risk | ❌ | No guarantee of real-time signals, ignore that condition. |
| Sign-In Risk | ❌ | No guarantee of real-time signals, ignore that condition. |
| User Risk | ❌ | No guarantee of real-time signals, ignore that condition. |
