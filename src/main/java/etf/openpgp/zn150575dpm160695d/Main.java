package etf.openpgp.zn150575dpm160695d;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;

import etf.openpgp.zn150575dpm160695d.crypto.KeyRings;
import etf.openpgp.zn150575dpm160695d.crypto.generators.RSAKeyPairGenerator;

import java.security.Security;

public class Main {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static KeyRings keyRings = new KeyRings(new RSAKeyPairGenerator());

    public static void main(String[] args) {
        App.app();
    }

}