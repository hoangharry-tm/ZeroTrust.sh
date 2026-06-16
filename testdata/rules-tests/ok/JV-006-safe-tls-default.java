// JV-006 SAFE: uses JVM default TLS — no custom TrustManager, no hostname override
package com.acmecorp.client;

import java.net.URL;
import java.net.HttpURLConnection;
import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class SafeHttpClient {

    /**
     * Fetch a URL using the JVM's default TLS validation.
     * No custom TrustManager — full certificate chain and hostname validation applies.
     */
    public static String fetchUrl(String urlStr) throws Exception {
        URL url = new URL(urlStr);
        // Safe: no custom HostnameVerifier set — default JVM validation used
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(10000);

        // No .setHostnameVerifier() call — uses JVM default
        // No custom SSLSocketFactory — uses JVM default trust store

        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            throw new RuntimeException("HTTP error: " + responseCode);
        }

        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line).append("\n");
        }
        return sb.toString();
    }
}
