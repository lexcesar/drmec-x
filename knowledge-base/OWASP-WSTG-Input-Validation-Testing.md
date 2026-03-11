# OWASP Web Security Testing Guide — Input Validation Testing

Source: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README

## 4.7 Input Validation Testing

Input validation is one of the most critical security controls. Improper input validation is the root cause of many vulnerability classes including injection, XSS, and buffer overflows.

### 4.7.1 Testing for Reflected Cross Site Scripting (XSS)
Reflected XSS occurs when user input is immediately returned by a web application in an error message, search result, or any response that includes input sent to the server as part of the request.

### 4.7.2 Testing for Stored Cross Site Scripting (XSS)
Stored XSS occurs when a web application gathers input from a user which might be malicious, and then stores that input for later display to other users. The input is not properly sanitized.

### 4.7.3 Testing for HTTP Verb Tampering
HTTP verb tampering tests the web application's response to different HTTP methods for the same resource. If access controls only check GET and POST, an attacker may bypass them using PUT, DELETE, or PATCH.

### 4.7.4 Testing for HTTP Parameter Pollution
HTTP Parameter Pollution (HPP) tests for the manipulation of HTTP parameters by injecting additional parameters with the same name, potentially bypassing input validation and WAF rules.

### 4.7.5 Testing for SQL Injection
SQL injection occurs when user input is not properly sanitized before being included in SQL queries. This allows attackers to read, modify, or delete database contents.

#### 4.7.5.1 Testing for Oracle SQL Injection
#### 4.7.5.2 Testing for MySQL SQL Injection
#### 4.7.5.3 Testing for SQL Server SQL Injection
#### 4.7.5.4 Testing for PostgreSQL SQL Injection
#### 4.7.5.5 Testing for MS Access SQL Injection
#### 4.7.5.6 Testing for NoSQL Injection
#### 4.7.5.7 Testing for ORM Injection
#### 4.7.5.8 Testing for Client-side SQL Injection

### 4.7.6 Testing for LDAP Injection
LDAP injection occurs when user input is incorporated into LDAP queries without proper sanitization, allowing attackers to modify query logic to bypass authentication or access unauthorized data.

### 4.7.7 Testing for XML Injection
XML injection tests whether it is possible to inject XML constructs into the application. This includes XML external entity (XXE) attacks that can lead to file disclosure, SSRF, and remote code execution.

### 4.7.8 Testing for SSI Injection
Server-Side Include injection allows attackers to inject directives into HTML pages that are executed by the web server before serving the page.

### 4.7.9 Testing for XPath Injection
XPath injection occurs when user input is used to construct XPath queries for XML data without proper sanitization.

### 4.7.10 Testing for IMAP/SMTP Injection
IMAP and SMTP injection tests whether mail commands can be injected through user input into mail server communications.

### 4.7.11 Testing for Code Injection
Code injection tests determine whether it is possible to inject code that is then executed by the web application. Includes testing for Python eval(), PHP eval(), and similar dangerous functions.

### 4.7.12 Testing for Command Injection (OS Command Injection)
OS command injection occurs when an application passes unsafe user-supplied data to a system shell. Attackers can use shell metacharacters (;, |, &&, ||, backticks) to chain commands.

Prevention: Use parameterized APIs, avoid shell=True, validate and sanitize all input, use allowlists for expected values.

### 4.7.13 Testing for Format String Injection
Format string vulnerabilities occur when user-supplied input is used directly as a format string parameter in functions like printf(), causing information disclosure or code execution.

### 4.7.14 Testing for Incubated Vulnerabilities
Incubated vulnerabilities are attacks that are stored by the application and triggered later, potentially in a different context or by a different user.

### 4.7.15 Testing for HTTP Incoming Requests (HTTP Request Smuggling)
HTTP request smuggling exploits discrepancies between how front-end and back-end servers interpret HTTP request boundaries.

### 4.7.16 Testing for Host Header Injection
Host header injection attacks exploit the trust applications place in the HTTP Host header, potentially leading to web cache poisoning, password reset poisoning, and SSRF.

### 4.7.17 Testing for Server-Side Template Injection (SSTI)
SSTI occurs when user input is embedded into server-side templates in an unsafe manner. This can lead to remote code execution. Common in Jinja2, Twig, Freemarker, and Velocity templates.

### 4.7.18 Testing for Server-Side Request Forgery (SSRF)
SSRF vulnerabilities allow attackers to force the server to make HTTP requests to arbitrary domains, potentially accessing internal services, cloud metadata endpoints, or other protected resources.

### 4.7.19 Testing for Mass Assignment
Mass assignment vulnerabilities occur when an application automatically binds HTTP request parameters to internal object properties without proper filtering, allowing attackers to modify fields they should not have access to.

### 4.7.20 Testing for CSV Injection
CSV injection (formula injection) occurs when user input is included in CSV exports without sanitization. Malicious formulas (=CMD(), =HYPERLINK()) can execute when opened in spreadsheet applications.

### 4.7.21 Testing for HTTP Response Splitting
HTTP response splitting occurs when user input is included in HTTP response headers without proper sanitization, allowing attackers to inject additional headers or create a second response.
