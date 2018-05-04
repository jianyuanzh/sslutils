package cc.databus.ssl.certificate;


import cc.databus.ssl.utils.PassAllHostnameVerifer;
import cc.databus.ssl.utils.TrustAllManager;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;

public class ServerCertificate {

    private static String ENABLE_CIPHERS = "enable.ciphers";
    private static String SOCKET_TIMEOUT_SECONDS_KEY = "socket.timeout.seconds";
    private static int SOCKET_TIMEOUT = 30_000;
    static {
        try {
            SOCKET_TIMEOUT = Integer.parseInt(System.getProperty(SOCKET_TIMEOUT_SECONDS_KEY, "30")) * 1000;
        }
        catch (Exception ignore) {
        }
    }


    // ==============================================================================================================

    private static String[] enabledCiphers() {
        String fromSysConf = System.getProperty(ENABLE_CIPHERS, "");
        if (fromSysConf.isEmpty()) {
            return new String[0];
        }
        else {
            return fromSysConf.split(",");
        }
    }

    private static SSLSocket createSSLSocket(CertHolderTrustAllManager trustAllManager, String host, int port) throws IOException, NoSuchAlgorithmException, KeyManagementException {
        Socket socket = new Socket();
        socket.setSoTimeout(SOCKET_TIMEOUT);
        socket.connect(new InetSocketAddress(host, port), SOCKET_TIMEOUT);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[] {trustAllManager}, new SecureRandom());
        SSLSocketFactory socketFactory = sslContext.getSocketFactory();

        SSLSocket sslSocket = (SSLSocket) socketFactory.createSocket(socket, host, port, true);
        HashSet<String> ciphers = new HashSet<>();
        String [] ciphersFromSysConf = enabledCiphers();

        if (ciphersFromSysConf.length == 0) {
            ciphers.addAll(Arrays.asList(sslSocket.getEnabledCipherSuites()));
            ciphers.add("SSL_RSA_WITH_RC4_128_SHA");
            ciphers.add("SSL_RSA_WITH_RC4_128_MD5");
            sslSocket.setEnabledCipherSuites(ciphers.toArray(new String[ciphers.size()]));
        }
        else {
            sslSocket.setEnabledCipherSuites(ciphersFromSysConf);
        }

        return sslSocket;
    }

    public static Certificate[] remoteCertificateByHandshake(String hostname, int port) throws NoSuchAlgorithmException, IOException, KeyManagementException {
        if (hostname == null || hostname.isEmpty()) {
            throw new IllegalArgumentException("should not provide empty hostname.");
        }

        String request = "GET / HTTP/1.1\r\nHost:" + hostname + ":" + port + "\r\nConnection:Close\r\nUser-Agent:SSLClient/1.0\r\n\r\n";

        CertHolderTrustAllManager trustAllManager = new CertHolderTrustAllManager();
        SSLSocket sslSocket = null;
        try {
            sslSocket = createSSLSocket(trustAllManager, hostname, port);

            OutputStreamWriter writer = new OutputStreamWriter(sslSocket.getOutputStream(), "utf-8");
            writer.write(request);
            writer.flush();
        }
        finally {
            if (sslSocket != null) {
                try {
                    sslSocket.close();
                }
                catch (Exception ignore){}
            }
        }

        return trustAllManager.serverCertificates;
    }

    private static class CertHolderTrustAllManager implements X509TrustManager {

        private volatile X509Certificate[] serverCertificates = null;
        private volatile X509Certificate[] clientCertificates = null;
        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            clientCertificates = x509Certificates;
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            serverCertificates = x509Certificates;
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }
    /// -------------------------------------------------------------------------------------------------------------

    public static Certificate[] remoteCertificate(String urlStr) throws IOException, NoSuchAlgorithmException, KeyManagementException {
        if (urlStr == null || urlStr.isEmpty()) {
            throw new IllegalArgumentException("should not provide empty url.");
        }

        if (!urlStr.toUpperCase().startsWith("HTTPS://")) {
            throw new IllegalArgumentException(urlStr + " not a https url.");
        }

        TrustAllManager trustAllManager = new TrustAllManager();
        PassAllHostnameVerifer hostnameVerifer = new PassAllHostnameVerifer();

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{trustAllManager}, new SecureRandom());

        HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier(hostnameVerifer);
        URL url = new URL(urlStr);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.connect();

        return connection.getServerCertificates();
    }

    /**
     * Usage:
     *      serverCipher [url]
     *      serverCipher [hostname] [port]
     * Useful options:
     *      -Denable.ciphers=TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 to specify enabled ciphers.
     *
     *
     * @param args
     * @throws IOException
     * @throws KeyManagementException
     * @throws NoSuchAlgorithmException
     */
    public static void main(String[] args) throws IOException, KeyManagementException, NoSuchAlgorithmException {

        if (args.length < 1) {
            System.out.println("Usage:" +
                                "\n\tserverCert <url>" +
                                "\n\tserverCert <hostname> <port>");
            return;
        }

        if (args.length == 1) {
            Certificate[] certs = remoteCertificate(args[0]);
            System.out.println("Certificate count: " + certs.length);
            for (Certificate cert : certs) {
                System.out.println("=========================================================================");
                System.out.println(cert.toString());
            }
        }
        else {
            Certificate[] certs = remoteCertificateByHandshake(args[0], Integer.parseInt(args[1]));
            System.out.println("Certificate count: " + certs.length);
            for (Certificate cert : certs) {
                System.out.println("=========================================================================");
                System.out.println(cert.toString());
            }
        }
    }
}
