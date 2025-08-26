package com.example.emproxy.radius;

import java.security.SecureRandom;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

import com.example.emproxy.radius.server.RadiusServerWithOTP;

@SpringBootApplication
public class EmProxyForRadiusApplication implements CommandLineRunner {

    @Value("${radius.authenticationPort}")
    private Integer authenticationPort;

    @Value("${radius.accountingPort}")
    private Integer accountingPort;

    public static void main(String[] args) {
        SpringApplication.run(EmProxyForRadiusApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        initializeRadiusServer();
    }

    private void initializeRadiusServer() {
        RadiusServerWithOTP server = new RadiusServerWithOTP();
        server.setAuthPort(authenticationPort);
        server.setAcctPort(accountingPort);
        server.start(true, true);
    }

    @Bean
    RestTemplate restTemplate() {
        ignoreCertificates();
        return new RestTemplate();
    }

    private void ignoreCertificates() {
    	TrustManager[] trustAllCerts = new TrustManager[] {
    			new CustomTrustManager()
    	};

    	try {
    		SSLContext sc = SSLContext.getInstance("TLS");
    		sc.init(null, trustAllCerts, new SecureRandom());
    		HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    		HttpsURLConnection.setDefaultHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());
    	} catch (Exception e) {
    		e.printStackTrace();
    	}

    }
}