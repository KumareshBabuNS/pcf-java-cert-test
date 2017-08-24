/**
 * Small Spring boot app that lists all certs in a trust store
 * 
 * Permission to copy, modify etc provided the original author and copyright notice is kept
 * 
 * Copyright Pivotal Inc.
 * 
 * @Author Matt Day, Pivotal
 */
package io.pivotal.mday.pcf.cert.test;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class TestApplication {

	public static void main(String[] args) {
		SpringApplication.run(TestApplication.class, args);
	}

	/**
	 * Loops through all certs in a trust store and prints the subject common
	 * names (CN)
	 */
	@GetMapping("/")
	public List<String> getCertificateList() throws Exception {
		TrustManagerFactory trustManagerFactory = TrustManagerFactory
				.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		List<String> certs = new ArrayList<>(50);
		trustManagerFactory.init((KeyStore) null);
		final String regex = ".*Subject:.*CN=(.*?),.*";

		// List all trust managers
		for (TrustManager t : trustManagerFactory.getTrustManagers()) {
			// Cast from a trust manager to a list of certs to loop through
			for (X509Certificate c : ((X509TrustManager) t).getAcceptedIssuers()) {
				// Match the Subject common name (messy code but what the hey!):
				final String certString = c.toString().replaceAll("\n", "");
				if (certString.matches(regex)) {
					certs.add(certString.replaceAll(regex, "$1"));
				}
			}
		}
		return certs;
	}
}
