// JV-006 V2/A: Named class with empty X509TrustManager.checkServerTrusted()
// Also V1/A2: checkClientTrusted empty on anonymous class
package com.acmecorp.client;

import javax.net.ssl.*;
import java.security.cert.X509Certificate;

// VULN A (V2): named class implementing X509TrustManager with empty body
class NoopTrustManager implements X509TrustManager {
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
        // empty — accepts all certs
    }
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
    }
    public X509Certificate[] getAcceptedIssuers() {
        return null;
    }
}

public class NamedTrustManagerClient {

    public static void main(String[] args) throws Exception {
        // VULN E: SSLContext.init with no-op TrustManager
        SSLContext sslCtx = SSLContext.getInstance("TLS");
        sslCtx.init(null, new TrustManager[]{new NoopTrustManager()}, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sslCtx.getSocketFactory());

        // VULN F: setHostnameVerifier lambda always true
        HttpsURLConnection.setDefaultHostnameVerifier((host, session) -> true);
    }
}
