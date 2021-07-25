package com.restclient.testdemo;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.junit.Before;
import org.junit.Test;

/**
 * Unit test for simple App.
 */
public class AppTest 
{
    private static final String JAVA_KEYSTORE = "jks";   
//    private static final String CLIENT_TRUSTSTORE = "D:\\working\\testing\\ssl\\client\\client_truststore.jks";  
    private static final String CLIENT_TRUSTSTORE = "ssl/clientTrustStore.jks";
    private static final char[] storePassword = "P@ssw0rd".toCharArray();   
    
//	private static final boolean ONE_WAY_SSL = false; // no client certificates
//	private static final String SERVER_KEYSTORE = "ssl/server_keystore.jks"; 
    
    private CloseableHttpClient httpclient; 
	
    @Before 
    public void setUp() throws Exception {
    	httpclient = HttpClients.createDefault(); 
    }
    
	/**
     * Rigorous Test :-)
     */
	@Test
    public void main() throws Exception {
    	String sUrl = "https://localhost:8443/customer/1";  
//    	String CLIENT_KEYSTORE = "D:\\working\\testing\\ssl\\server\\keystore.p12"; 
    	int port = 8080; 
    	int sslPort = 8443; 
    	
//    	System.out.println("------------ test start ---------------");
    	
    	// The server certificate was imported into the client's TrustStore (using keytool -import) 
    	KeyStore clientTrustStore = getStore(CLIENT_TRUSTSTORE, storePassword); 
    	
    	SSLContext sslContext = new SSLContextBuilder().loadTrustMaterial(clientTrustStore, new TrustSelfSignedStrategy()).build(); 
    	
    	// if want to lossen the hostname checking, use SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER 
    	// but not recommended 
    	SSLConnectionSocketFactory connectionFactory = new SSLConnectionSocketFactory(sslContext, SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER); 
    	
    	httpclient = HttpClients.custom().setSSLSocketFactory(connectionFactory).build();
//    	httpclient = HttpClients.custom().setSslcontext(sslContext).build();  

    	/*
	    	The HTTP client will now validate the server's presented certificate using its TrustStore.
	     	Since the cert was imported to the client's TrustStore explicitly (see above), the
	     	certificate will validate and the request will succeed
	    */
    	HttpGet getRequest = new HttpGet(sUrl); 
		getRequest.addHeader("accept", "application/json"); 

//      assertThat(httpResponse.getStatusLine().getStatusCode(), equalTo(200));
		
		HttpResponse response = httpclient.execute(getRequest); 
		HttpEntity httpEntity = response.getEntity(); 
		String strResJson = EntityUtils.toString(httpEntity); 
		
		System.out.println("return code=" + response.getStatusLine().getStatusCode());   
		System.out.println("return json=" + strResJson); 
    	
//    	System.setProperty("javax.net.ssl.keyStore", ""); 
//    	System.setProperty("javax.net.ssl.keyStorePassword", "P@ssw0rd");
//    	System.setProperty("javax.net.ssl.keyStoreType", "p12");
//    	System.setProperty("javax.net.ssl.trustStore", "");
//    	System.setProperty("javax.net.ssl.trustStorePassword", "P@ssw0rd");
    	
//    	SSLContext sslContext = SSLContexts.custom()
//    			.loadKeyMaterial(getStore(CLIENT_KEYSTORE, storePassword.toCharArray())
//    					, storePassword.toCharArray()) 
//    			.loadTrustMaterial(getStore(CLIENT_TRUSTSTORE, storePassword.toCharArray())
//    					, new TrustSelfSignedStrategy())
//    			.useProtocol("TLS").build(); 
//    	
//    	SSLConnectionSocketFactory connectionFactory = new SSLConnectionSocketFactory(sslContext, new DefaultHostnameVerifier()); 
//    	
//		HttpClient httpClient = HttpClientBuilder.create().setSSLSocketFactory(connectionFactory).build(); 
		
		System.out.println("------------ test end ---------------");
		System.exit(0);
	}
    
    
    /**
     * KeyStores provide credentials, TrustStores verify credentials.
     *
     * Server KeyStores stores the server's private keys, and certificates for corresponding public
     * keys. Used here for HTTPS connections over localhost.
     *
     * Client TrustStores store servers' certificates.
     */
    protected KeyStore getStore(String storeFileName, char[] password) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
    	KeyStore store = KeyStore.getInstance(JAVA_KEYSTORE); 
    	URL url = getClass().getClassLoader().getResource(storeFileName);   
    	InputStream inputStream = url.openStream(); 
    	try {
    		store.load(inputStream, password);
    	} finally {
    		inputStream.close(); 
    	}
    	return store; 
    }
    
        
	/**
	* KeyManagers decide which authentication credentials (e.g. certs) should be sent to the remote
	* host for authentication during the SSL handshake.
	*
	* Server KeyManagers use their private keys during the key exchange algorithm and send
	* certificates corresponding to their public keys to the clients. The certificate comes from
	* the KeyStore.
	*/
    protected KeyManager[] getKeyManagers(KeyStore store, final char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException { 
    	KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()); 
    	keyManagerFactory.init(store, password);  
    	
    	return keyManagerFactory.getKeyManagers(); 
    }
    

	/**
	* TrustManagers determine if the remote connection should be trusted or not.
	*
	* Clients will use certificates stored in their TrustStores to verify identities of servers.
	* Servers will use certificates stored in their TrustStores to verify identities of clients.
	*/
    protected TrustManager[] getTrustManagers(KeyStore store) throws NoSuchAlgorithmException, KeyStoreException{
    	TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); 
    	trustManagerFactory.init(store); 
    	
    	return trustManagerFactory.getTrustManagers(); 
    }
    
    
    /**
    * Create an SSLContext for the server using the server's JKS. This instructs the server to
    * present its certificate when clients connect over HTTPS.
    */
    protected SSLContext createServerSSLContext(String storeFileName, char[] password) throws CertificateException, NoSuchAlgorithmException, KeyStoreException,
    					IOException, UnrecoverableKeyException, KeyManagementException {
    	KeyStore serverKeyStore = getStore(storeFileName, password); 
    	KeyManager[] serverKeyManagers = getKeyManagers(serverKeyStore, password); 
    	TrustManager[] serverTrustManagers = getTrustManagers(serverKeyStore); 
    	
    	SSLContext sslContext = SSLContexts.custom().useProtocol("TLS").build(); 
    	sslContext.init(serverKeyManagers, serverTrustManagers, new SecureRandom());  
    	
    	return sslContext; 
    }
    
    
}
