// JV-006 EDGE/SAFE: HostnameVerifier.verify() that does a real check (not always true)
// Near-miss: implements HostnameVerifier but with real logic
package com.acmecorp.client;

import javax.net.ssl.*;
import java.util.Arrays;
import java.util.List;

public class PinnedHostnameVerifier implements HostnameVerifier {

    private final List<String> allowedHosts;

    public PinnedHostnameVerifier(String... hosts) {
        this.allowedHosts = Arrays.asList(hosts);
    }

    @Override
    public boolean verify(String hostname, SSLSession session) {
        // Safe: real check — only allows explicitly listed hostnames
        return allowedHosts.contains(hostname);
    }
}

// Also safe: verify() returns the result of a real check, not literal true
class AllowCorporateHostsVerifier implements HostnameVerifier {

    @Override
    public boolean verify(String hostname, SSLSession session) {
        // Real logic — checks domain suffix
        return hostname != null &&
               (hostname.endsWith(".acmecorp.com") || hostname.equals("api.trusted-partner.com"));
    }
}
