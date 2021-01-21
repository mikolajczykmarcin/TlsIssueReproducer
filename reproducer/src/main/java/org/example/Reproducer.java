package org.example;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.security.*;
import java.security.cert.CertificateException;

public class Reproducer {
    private static final String URL = "https://open.api.mbank.pl";
    private static final String TRUST_PATH = "reproducer/resources/trust.jks";
    private static final String KEY_PATH = "reproducer/resources/key.jks";
    private static final char[] pass = "zaq1@WSX".toCharArray();

    public static void main(String[] args) throws Exception {
        setSystemProperties();
        loadTrustAndKeyStore();
        Reproducer r = new Reproducer();
        r.connect();
    }

    /**
     * open the ssl connection
     */
    private void connect() throws Exception {
        URL url = new URL(URL);

        URLConnection con = url.openConnection();

        printResponse(con.getInputStream());
    }

    /**
     * This method prints the contents of InputStream (a response from server).
     */
    private void printResponse(InputStream in) throws IOException {
        BufferedReader buf = new BufferedReader(new InputStreamReader(in));

        String inputLine;
        while ((inputLine = buf.readLine()) != null) {
            System.out.println(inputLine);
        }
    }

    private static void loadTrustAndKeyStore() {
        try {
            FileInputStream trustInputStream = new FileInputStream(TRUST_PATH);
            FileInputStream keyInputStream = new FileInputStream(KEY_PATH);

            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

            trustStore.load(trustInputStream, pass);
            keyStore.load(keyInputStream, pass);

            SSLContext context = SSLContext.getInstance("SSL");

            TrustManagerFactory trustFactoru = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            KeyManagerFactory keyFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

            trustFactoru.init(trustStore);
            keyFactory.init(keyStore, pass);

            context.init(keyFactory.getKeyManagers(), trustFactoru.getTrustManagers(), null);

            SSLContext.setDefault(context);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | KeyManagementException | UnrecoverableKeyException ex) {
            //Handle error
            ex.printStackTrace();
        }
    }

    private static void setSystemProperties() {
        System.setProperty("javax.net.debug", "ssl,handshake");
        System.setProperty("jdk.tls.namedGroups", "secp256r1");
        System.setProperty("jdk.tls.server.SignatureSchemes", "rsa_pkcs1_sha256");
        System.setProperty("jdk.tls.client.SignatureSchemes", "rsa_pkcs1_sha256");
    }
}