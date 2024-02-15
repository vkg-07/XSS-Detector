<p align="center">
<img src="https://github.com/vkg-07/XSS-Detector/blob/main/files/XSS_Detector.png">
</p>

This is a Burp Suite extension designed to detect different endpoints and validate possible XSS vulnerabilities in a given domain.


Endpoint Detection
------------------

When entering a domain, the extension will detect all endpoints of that domain with parameters (of type URL or body) that pass through the proxy. 
This is designed so that as the analyst is doing a recognition of the page, these endpoints are loaded into the extension.

Add an endpoint manually
------------------------

In addition to endpoint detection, it is possible to add endpoints manually, provided that the given endpoint domain has been specified in advance 
and at least one endpoint has been detected through the proxy.

Syntax: 

      POST /example/endpoint?p1=value&p2=value

Usage
-----
You must specify the domain of the site you are interested in, specify the port and protocol (or use the default ones).
As you browse the site, the requests that pass through the proxy will be automatically analyzed and filtered to detect possible vulnerable endpoints,
which you will be able to see in the extension window. You can also add endpoints manually.
When you have enough desired endpoints, you can start XSS Detector to detect which endpoints may be vulnerable to an XSS attack.
