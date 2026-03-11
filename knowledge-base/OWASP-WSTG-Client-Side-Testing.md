# OWASP Web Security Testing Guide — Client-Side Testing

Source: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/README

## 4.11 Client-Side Testing

Client-side vulnerabilities arise from improper handling of data and code in the user's browser. These vulnerabilities can be exploited without direct server-side interaction.

### 4.11.1 Testing for DOM-Based Cross Site Scripting
DOM-based XSS occurs when client-side JavaScript processes data from an untrusted source in an unsafe way, writing it back to the DOM. Unlike reflected or stored XSS, the payload never reaches the server.

Common sources: document.URL, document.location, document.referrer, window.name, location.hash
Common sinks: document.write(), innerHTML, eval(), setTimeout(), setInterval()

Prevention: Use textContent instead of innerHTML, avoid eval() and similar functions, sanitize all DOM inputs.

#### Testing for Self DOM Based XSS
Self-XSS variants where the user is tricked into executing malicious code in their own browser context.

### 4.11.2 Testing for JavaScript Execution
Evaluates risks associated with dynamic script execution. Tests whether user input can be injected into JavaScript execution contexts.

### 4.11.3 Testing for HTML Injection
Assesses improper HTML element handling. HTML injection allows attackers to inject arbitrary HTML content, potentially modifying the page structure or creating phishing interfaces.

### 4.11.4 Testing for Client-side URL Redirect
Tests open redirect vulnerabilities on the client tier. Unvalidated redirects can be used in phishing attacks, sending users to malicious sites via trusted domain URLs.

### 4.11.5 Testing for CSS Injection
Examines style-based injection vectors. CSS injection can be used to exfiltrate data, modify page appearance for phishing, or exploit browser-specific CSS features.

### 4.11.6 Testing for Client-side Resource Manipulation
Analyzes resource tampering possibilities where attackers can modify the resources loaded by the page (scripts, images, stylesheets) through parameter manipulation.

### 4.11.7 Testing for Cross Origin Resource Sharing (CORS)
Reviews cross-domain access policies. Misconfigured CORS headers (Access-Control-Allow-Origin: *) can allow unauthorized cross-origin data access.

Common misconfigurations:
- Wildcard origin (*)
- Reflecting the Origin header without validation
- Allowing credentials with wildcard origin
- Null origin whitelisting

### 4.11.8 Testing for Cross Site Flashing
Tests Flash-based security issues including improper allowScriptAccess and allowNetworking settings.

### 4.11.9 Testing for Clickjacking
Evaluates UI redressing attack vectors where transparent or opaque layers trick users into clicking on elements they cannot see.

Prevention: X-Frame-Options header, Content-Security-Policy frame-ancestors directive, JavaScript frame-busting code.

### 4.11.10 Testing for WebSockets
Assesses WebSocket protocol security including cross-site WebSocket hijacking, lack of authentication on WebSocket endpoints, and unencrypted WebSocket connections (ws:// vs wss://).

### 4.11.11 Testing for Web Messaging
Tests postMessage API vulnerabilities. Improper origin validation in message event handlers can allow cross-origin attacks.

### 4.11.12 Testing for Browser Storage
Reviews localStorage and sessionStorage security. Sensitive data stored in browser storage is accessible to any script running in the same origin, making it vulnerable to XSS attacks.

### 4.11.13 Testing for Cross Site Script Inclusion (CSSI/XSSI)
Evaluates whether sensitive data can be leaked through script includes across origins.

### 4.11.14 Testing for Reverse Tabnabbing
Tests window.opener exploitation where a page opened via target="_blank" can redirect the opener page to a phishing site.

Prevention: Use rel="noopener noreferrer" on links with target="_blank".

### 4.11.15 Testing for Client-side Template Injection
Assesses template engine vulnerabilities in client-side frameworks (AngularJS, Vue.js, React) where user input in template expressions can lead to code execution.
