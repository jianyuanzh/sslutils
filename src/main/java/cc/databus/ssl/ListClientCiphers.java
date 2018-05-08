package cc.databus.ssl;

import javax.net.ssl.SSLSocketFactory;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

public class ListClientCiphers {
    public static void main(String[] args) {

        boolean showAll = false;
        if (args.length > 0) {
            showAll = Boolean.valueOf(args[0]);
        }

        SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();

        String[] defaultCiphers = sslSocketFactory.getDefaultCipherSuites();
        String[] availableCiphers = sslSocketFactory.getSupportedCipherSuites();

        TreeMap<String, Boolean> ciphers = new TreeMap<String, Boolean>();

        // all supported ciphers
        for (String availableCipher : availableCiphers) {
            ciphers.put(availableCipher, Boolean.FALSE);
        }

        // all enabled ciphers
        for (String defaultCipher : defaultCiphers) {
            ciphers.put(defaultCipher, Boolean.TRUE);
        }


        for (Map.Entry<String, Boolean> stringBooleanEntry : ciphers.entrySet()) {
            boolean enabled = Boolean.TRUE.equals(((Map.Entry) stringBooleanEntry).getValue());
            if (!enabled && showAll) {
                System.out.println("-" + ((Map.Entry) stringBooleanEntry).getKey());
            } else {
                System.out.println("*" + ((Map.Entry) stringBooleanEntry).getKey());
            }
        }

    }
}
