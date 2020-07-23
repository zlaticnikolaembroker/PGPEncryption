package etf.openpgp.indeksi;

import etf.openpgp.indeksi.crypto.RSAKeyRing;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;

import java.security.Security;

public class Main {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws PGPException {
        RSAKeyRing.printSecretKeyRing();
//        RSAKeyRing.exportSecretKeyRing();
        RSAKeyRing.exportPublicKeyRing();
        App.app();
    }

}