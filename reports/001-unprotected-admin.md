# Security Assessment 001 — Unprotected Admin Functionality

**Platform:** PortSwigger Web Security Academy  
**Category:** Broken Access Control  
**Status:** Solved  
**Environment:** Authorized training laboratory

## Objective
Identify an administrative function accessible without proper authorization.

## Methodology
1. Explored the training application.
2. Inspected the `robots.txt` file.
3. Discovered the `/administrator-panel` path.
4. Accessed the administration interface without logging in.
5. Completed the lab's required user-deletion action.

## Finding
The application did not enforce adequate authorization checks on its administrative interface.

## Impact
Unauthenticated users could access privileged administrative functions, including user account deletion.

## Root Cause
Missing server-side authorization checks for administrative functionality.

## Remediation
- Enforce authorization checks on every administrative request.
- Implement role-based access control (RBAC).
- Deny access by default.
- Do not rely on hidden URLs or `robots.txt` to protect sensitive functionality.

## Lessons Learned
Discovering a hidden endpoint is not a vulnerability by itself. A security issue occurs when unauthorized users can perform privileged actions.

## Ethical Scope
This assessment was performed exclusively in an authorized PortSwigger training lab.
