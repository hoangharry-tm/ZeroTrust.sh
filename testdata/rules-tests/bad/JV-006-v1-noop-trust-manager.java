// JV-006 V1/A,B: empty X509TrustManager and HostnameVerifier always returning true
// Realistic AI-generated HTTP client config — TLS validation completely disabled
package com.acmecorp.client;

import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import java.net.URL;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class InsecureHttpClient {

    /**
     * Create an HTTPS connection that accepts all certificates.
     * WARNING: This disables ALL TLS security.
     */
    public static String fetchUrl(String urlStr) throws Exception {
        // VULN A: anonymous X509TrustManager with empty checkServerTrusted
        TrustManager[] trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    // intentionally empty — accepts all certificates
                }
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                    // intentionally empty
                }
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[]{};
                }
            }
        };

        SSLContext sslCtx = SSLContext.getInstance("TLS");
        sslCtx.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sslCtx.getSocketFactory());

        // VULN B: HostnameVerifier that always returns true
        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;  // accepts any hostname — VULN
            }
        });

        URL url = new URL(urlStr);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();

        // VULN F: lambda HostnameVerifier
        conn.setHostnameVerifier((host, session) -> true);  // VULN: lambda always true

        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        return sb.toString();
    }
}
