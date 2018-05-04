package cc.databus.ssl.utils;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

/**
 * Created by vincent on 04/05/2018.
 */
public class PassAllHostnameVerifer implements HostnameVerifier {
    @Override
    public boolean verify(String s, SSLSession sslSession) {
        return true;
    }
}
