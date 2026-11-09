# Security Assessment 002 — Cookie-Based Privilege Escalation

**Platform:** PortSwigger Web Security Academy  
**Lab:** User Role Controlled by Request Parameter  
**Category:** Broken Access Control  
**Status:** Solved  
**Environment:** Authorized training lab

## Objective
Test whether administrative access is controlled by a client-modifiable cookie.

## Methodology
1. Logged in using the provided standard user account.
2. Inspected HTTP requests and responses using Burp Suite.
3. Identified the `Admin=false` cookie.
4. Sent a request to Burp Repeater.
5. Changed the cookie value to `Admin=true`.
6. Requested the `/admin` endpoint.
7. Confirmed that administrative functionality was accessible.
8. Completed the lab's required action.

## Finding
The application trusted a client-controlled cookie to determine administrative privileges.

## Impact
An ordinary user could gain administrative access and perform privileged operations, including deleting user accounts.

## Root Cause
Administrative authorization relied on a value that could be modified by the client.

## Remediation
- Enforce authorization checks on the server.
- Never trust client-controlled role indicators.
- Associate permissions with authenticated identities on the server.
- Apply least privilege and deny access by default.
- Validate authorization on every privileged request.

## Lessons Learned
Authentication and authorization are different security controls. A logged-in user must not be able to gain elevated privileges by modifying request parameters or cookies.

## Ethical Scope
All testing was performed exclusively within an authorized PortSwigger training laboratory.
