package cc.databus.ssl

import javax.net.ssl.SSLSocketFactory


String[] opsSupported = ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                         "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                         "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
                         "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
                         "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                         "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                         "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                         "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                         "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                         "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                         "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                         "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                         "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                         "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
                         "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                         "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
                         "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
                         "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
]

SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();

Set<String> defaultCiphers = new HashSet(Arrays.asList(sslSocketFactory.getDefaultCipherSuites()))


List<String> supported = new ArrayList<>()
List<String> notSupoorted = new ArrayList<>()

for (String cipher : opsSupported) {
    if (defaultCiphers.contains(cipher)) {
        supported.add(cipher)
    }
    else {
        notSupoorted.add(cipher)
    }
}

println "------- Client supported --------"
for (String cp : supported) {
    println cp
}

println "\n------- Client not supported --------"
for (String cp : notSupoorted) {
    println cp
}