package etf.openpgp.zn150575dpm160695d.crypto;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPContentVerifier;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilder;

import etf.openpgp.zn150575dpm160695d.front.InfoScreen;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Base64;

public class Verifier {

    private static final int BUFFER_SIZE = 1 << 16; //64k

    private final KeyRings keyRings;

    public Verifier(KeyRings keyRings) {
        this.keyRings = keyRings;
    }

    public void verifySignature(PGPSignatureList signatureList, String pathToSignature) {
        int lastSeparatorLocation = pathToSignature.lastIndexOf(File.separator);
        String path = pathToSignature.substring(0, lastSeparatorLocation);
        String signatureFileName = pathToSignature.substring(lastSeparatorLocation + 1);
        // potpis mora biti u formatu fileToVerify.initialExtension.[sig|asc|someOtherExtension]
        String fileToVerifyName = path.concat(File.separator).concat(signatureFileName.substring(0, signatureFileName.lastIndexOf('.')));

        try (FileInputStream fileToVerify = new FileInputStream(fileToVerifyName)) {
            PGPSignature pgpSignature = signatureList.get(0);
            PGPPublicKey publicKey = keyRings.getPublicKeyRings().getPublicKey(pgpSignature.getKeyID());
            
            byte[] buffer = new byte[BUFFER_SIZE];
            int len;


            pgpSignature.initVerify(publicKey, "BC");
            while ((len = fileToVerify.read(buffer)) > 0) {
                pgpSignature.update(buffer, 0, len);
            }

            String labelText = "";
            if (pgpSignature.verify()) {
            	labelText = "Signature is verified, signed by " + publicKey.getUserIDs().next();
            } else {
            	labelText = "Signature is not verified.";
            }
            	
            InfoScreen screen = new InfoScreen("Signature verification", labelText);
            screen.showAndWait();

        } catch (PGPException | IOException | NoSuchProviderException | SignatureException e) {
            e.printStackTrace();
        }
    }

}
