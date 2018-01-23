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
        for (int i = 0; i < availableCiphers.length; i++) {
            ciphers.put(availableCiphers[i], Boolean.FALSE);
        }

        // all enabled ciphers
        for (int i=0; i< defaultCiphers.length; i++) {
            ciphers.put(defaultCiphers[i], Boolean.TRUE);
        }


        for (Iterator i = ciphers.entrySet().iterator(); i.hasNext(); ) {
            Map.Entry cipher = (Map.Entry) i.next();
            boolean enabled = Boolean.TRUE.equals(cipher.getValue());
            if (!enabled && showAll) {
                System.out.println("-" + cipher.getKey() );
            }
            else {
                System.out.println("*" + cipher.getKey());
            }
        }

    }
}
