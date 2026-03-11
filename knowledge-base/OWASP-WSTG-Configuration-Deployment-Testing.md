# OWASP Web Security Testing Guide — Configuration and Deployment Management Testing

Source: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README

## 4.2 Configuration and Deployment Management Testing

### 4.2.1 Test Network Infrastructure Configuration
Evaluation of network setup security. Misconfigured network infrastructure can allow unauthorized access, data leakage, and service disruption.

### 4.2.2 Test Application Platform Configuration
Examination of platform-level settings. Default configurations of web servers, application servers, and frameworks often include unnecessary features, sample applications, and debugging settings that can be exploited.

### 4.2.3 Test File Extensions Handling for Sensitive Information
Review of how file types are managed. Improper handling of file extensions can expose sensitive information such as source code, configuration files, or backup data.

### 4.2.4 Review Old Backup and Unreferenced Files for Sensitive Information
Discovery of exposed archived data. Old backup files, unreferenced pages, and forgotten files may contain sensitive information including credentials, database dumps, and source code.

### 4.2.5 Enumerate Infrastructure and Application Admin Interfaces
Identification of administrative access points. Admin interfaces are high-value targets that often have elevated privileges and may lack proper access controls.

### 4.2.6 Test HTTP Methods
Validation of allowed HTTP verbs. Unnecessary HTTP methods (PUT, DELETE, TRACE, CONNECT) may allow attackers to modify server-side content or perform cross-site tracing attacks.

### 4.2.7 Test HTTP Strict Transport Security (HSTS)
Verification of HSTS implementation. Without HSTS, users may be vulnerable to SSL stripping attacks and protocol downgrade attacks.

### 4.2.8 Test RIA Cross Domain Policy
Assessment of Rich Internet Application boundaries. Overly permissive crossdomain.xml or clientaccesspolicy.xml files can allow unauthorized cross-domain data access.

### 4.2.9 Test File Permission
Verification of proper access controls on the file system. Incorrect file permissions can allow unauthorized read, write, or execute access to sensitive files.

### 4.2.10 Test for Subdomain Takeover
Detection of vulnerable subdomains. Dangling DNS entries pointing to deprovisioned cloud services can be claimed by attackers to host malicious content under a trusted domain.

### 4.2.11 Test Cloud Storage
Evaluation of cloud resource security. Misconfigured cloud storage buckets (S3, Azure Blob, GCS) can expose sensitive data to unauthorized access.

### 4.2.12 Test for Content Security Policy (CSP)
Review of CSP headers. A missing or misconfigured Content Security Policy allows cross-site scripting, clickjacking, and other injection attacks.

### 4.2.13 Test for Path Confusion
Identification of path-based vulnerabilities. Path confusion attacks exploit discrepancies between how web servers and applications interpret URL paths.

### 4.2.14 Test for Other HTTP Security Header Misconfigurations
Comprehensive header analysis including X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and Cache-Control headers.
