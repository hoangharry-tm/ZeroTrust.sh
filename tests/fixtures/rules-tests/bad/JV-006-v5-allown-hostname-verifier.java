// JV-006 V7/B: ALLOW_ALL_HOSTNAME_VERIFIER and named class returning true
package com.acmecorp.client;

import javax.net.ssl.*;

// VULN B (V2): named class implementing HostnameVerifier returning true
class PermitAllHostnameVerifier implements HostnameVerifier {
    public boolean verify(String hostname, SSLSession session) {
        return true; // accepts any hostname
    }
}

public class HostnameBypassClient {

    public void configure() throws Exception {
        // VULN B: ALLOW_ALL_HOSTNAME_VERIFIER usage
        HttpsURLConnection.setDefaultHostnameVerifier(
            (HostnameVerifier) SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER
        );
    }
}
