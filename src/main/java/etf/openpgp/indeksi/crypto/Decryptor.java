package etf.openpgp.indeksi.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Iterator;

public class Decryptor {
    private static final int BUFFER_SIZE = 1 << 16; // 64k

    private final KeyRings keyRings;

    public Decryptor(KeyRings keyRings) {
        this.keyRings = keyRings;
    }
    
    private static PGPPrivateKey findSecretKey(InputStream keyIn, long keyID, char[] pass)
            throws IOException, PGPException, NoSuchProviderException
        {
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                org.bouncycastle.openpgp.PGPUtil.getDecoderStream(keyIn));
     
            PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);
     
            if (pgpSecKey == null) {
                return null;
            }
     
            return pgpSecKey.extractPrivateKey(pass, "BC");
        }
    
    public static void decryptFile(InputStream in, OutputStream out, InputStream keyIn, char[] passwd)
            throws Exception
        {
            Security.addProvider(new BouncyCastleProvider());
     
            in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);
     
            PGPObjectFactory pgpF = new PGPObjectFactory(in);
            PGPEncryptedDataList enc;
     
            Object o = pgpF.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            if (o instanceof  PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList) o;
            } else {
                enc = (PGPEncryptedDataList) pgpF.nextObject();
            }
     
            //
            // find the secret key
            //
            Iterator<PGPPublicKeyEncryptedData> it = enc.getEncryptedDataObjects();
            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe = null;
     
            while (sKey == null && it.hasNext()) {
                pbe = it.next();
     
                sKey = findSecretKey(keyIn, pbe.getKeyID(), passwd);
            }
     
            if (sKey == null) {
                throw new IllegalArgumentException("Secret key for message not found.");
            }
     
            InputStream clear = pbe.getDataStream(sKey, "BC");
     
            PGPObjectFactory plainFact = new PGPObjectFactory(clear);
     
            Object message = plainFact.nextObject();
     
            if (message instanceof  PGPCompressedData) {
                PGPCompressedData cData = (PGPCompressedData) message;
                PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream());
     
                message = pgpFact.nextObject();
            }
     
            if (message instanceof  PGPLiteralData) {
                PGPLiteralData ld = (PGPLiteralData) message;
     
                InputStream unc = ld.getInputStream();
                int ch;
     
                while ((ch = unc.read()) >= 0) {
                    out.write(ch);
                }
            } else if (message instanceof  PGPOnePassSignatureList) {
                throw new PGPException("Encrypted message contains a signed message - not literal data.");
            } else {
                throw new PGPException("Message is not a simple encrypted file - type unknown.");
            }
     
            if (pbe.isIntegrityProtected()) {
                if (!pbe.verify()) {
                    throw new PGPException("Message failed integrity check");
                }
            }
        }
}