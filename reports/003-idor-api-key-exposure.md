# Security Assessment 003 — IDOR and API Key Exposure

**Platform:** PortSwigger Web Security Academy  
**Lab:** User ID Controlled by Request Parameter  
**Category:** Broken Access Control / IDOR  
**Status:** Solved  
**Environment:** Authorized Training Lab

## 1. Objective

Identify an insecure direct object reference vulnerability that allows a regular user to access another user's sensitive information.

## 2. Tools Used

- Burp Suite Community Edition
- Web Browser
- HTTP Request Analysis

## 3. Methodology

1. Logged in using the provided account `wiener`.
2. Opened the My Account page.
3. Identified the user ID parameter in the URL.
4. Changed the parameter from `wiener` to `carlos`.
5. Observed that the application returned Carlos's account information.
6. Confirmed that the exposed information included an API key.
7. Completed the lab using the required solution submission.

## 4. Vulnerability

The application failed to verify whether the authenticated user was authorized to access the requested account.

**Example request:**

```http
GET /my-account?id=carlos HTTP/1.1
```

## 5. Security Impact

An attacker could access another user's sensitive account information, including API keys, potentially leading to further unauthorized access.

## 6. Root Cause

Missing object-level authorization checks on the server.

## 7. Recommended Remediation

- Enforce authorization checks on every request.
- Verify ownership of the requested resource.
- Apply least-privilege access controls.
- Avoid exposing sensitive API keys unnecessarily.
- Monitor unauthorized access attempts.

## 8. Lessons Learned

Authentication does not automatically grant permission to access other users' resources. Every request must be checked for proper authorization.

## 9. Ethical Scope

This assessment was conducted exclusively within an authorized PortSwigger training environment. Sensitive credentials and API keys have been excluded from this report.
