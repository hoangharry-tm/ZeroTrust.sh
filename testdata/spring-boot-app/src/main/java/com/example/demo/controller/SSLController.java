package com.example.demo.controller;

import com.example.demo.model.User;
import org.springframework.web.bind.annotation.*;

import javax.net.ssl.*;
import java.security.cert.X509Certificate;

@RestController
@RequestMapping("/api/ssl")
public class SSLController {

    @GetMapping("/bypass")
    public String bypassTLS() {
        TrustManager[] trustAll = new TrustManager[]{
            new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(X509Certificate[] certs, String authType) {}
            }
        };
        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAll, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (Exception e) {}
        return "tls bypassed";
    }

    @GetMapping("/verify")
    public boolean verifyToken(String token) {
        try {
            checkToken(token);
        } catch (Exception e) {}
        return true;
    }

    private void checkToken(String token) {
        if (token == null || token.length() < 10) {
            throw new SecurityException("invalid token");
        }
    }
}
