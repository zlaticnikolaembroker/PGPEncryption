package etf.openpgp.indeksi;

import etf.openpgp.indeksi.crypto.KeyRings;
import etf.openpgp.indeksi.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;

import java.security.Security;

public class Main {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static KeyRings keyRings = new KeyRings(new RSAKeyPairGenerator());

    public static void main(String[] args) {
        keyRings.printSecretKeyRing();
//        keyRings.exportPublicKeyRing();
//        keyRings.exportSecretKeyRing();
        App.app();
    }

}