package com.example.emproxy.radius;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

class CustomTrustManager implements X509TrustManager {
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    @Override
    public void checkClientTrusted(X509Certificate[] certs, String authType) 
            throws CertificateException {
        validateCertificates(certs, false);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] certs, String authType) 
            throws CertificateException {
        validateCertificates(certs, true);
    }

    private void validateCertificates(X509Certificate[] certs, boolean isServerAuth) 
            throws CertificateException {
        validateCertificateArray(certs);
        
        for (X509Certificate cert : certs) {
            validateSingleCertificate(cert, isServerAuth);
        }
    }

    private void validateCertificateArray(X509Certificate[] certs) throws CertificateException {
        if (certs == null || certs.length == 0) {
            throw new CertificateException("No certificates provided");
        }
    }

    private void validateSingleCertificate(X509Certificate cert, boolean isServerAuth) 
            throws CertificateException {
        // Verify certificate is not expired and not yet valid
        cert.checkValidity();

        // Verify certificate signature
        verifyCertificateSignature(cert);

        // Additional server-specific validation
        if (isServerAuth) {
            validateServerAuthentication(cert);
        }
    }

    private void verifyCertificateSignature(X509Certificate cert) throws CertificateException {
        try {
            cert.verify(cert.getPublicKey());
        } catch (Exception e) {
            throw new CertificateException("Certificate validation failed", e);
        }
    }

    private void validateServerAuthentication(X509Certificate cert) throws CertificateException {
        boolean[] keyUsage = cert.getKeyUsage();
        if (keyUsage != null && !keyUsage[0]) {
            throw new CertificateException("Certificate not valid for server authentication");
        }
    }
}