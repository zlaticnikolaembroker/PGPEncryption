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
    
    private PGPPrivateKey findSecretKey(long keyID, char[] password)
            throws Exception
        {
     
            PGPSecretKey pgpSecKey = this.keyRings.getSecretKeyRings().getSecretKey(keyID);
     
            if (pgpSecKey == null) {
                return null;
            }

            boolean passMatched = this.keyRings.verifySecretKeyPassword(keyID, new String(password));
            
            if (!passMatched) {
            	throw new Exception("Pass don't match");
            }
     
            return pgpSecKey.extractPrivateKey(password, "BC");
        }
    
    public void decryptFile(InputStream in, OutputStream out, char[] passwd)
            throws Exception
        {
            Security.addProvider(new BouncyCastleProvider());
     
            in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);
     
            PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(in);
            PGPEncryptedDataList encryptedDataList;
     
            Object pgpObject = pgpObjectFactory.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            if (pgpObject instanceof  PGPEncryptedDataList) {
                encryptedDataList = (PGPEncryptedDataList) pgpObject;
            } else {
            	encryptedDataList = (PGPEncryptedDataList) pgpObjectFactory.nextObject();
            }
     
            //
            // find the secret key
            //
            Iterator<PGPPublicKeyEncryptedData> publicKeyEncryptedDataIterator = encryptedDataList.getEncryptedDataObjects();
            PGPPrivateKey secretKey = null;
            PGPPublicKeyEncryptedData pbe = null;
     
            while (secretKey == null && publicKeyEncryptedDataIterator.hasNext()) {
                pbe = publicKeyEncryptedDataIterator.next();
     
                secretKey = this.findSecretKey(pbe.getKeyID(), passwd);
            }
     
            if (secretKey == null) {
                throw new IllegalArgumentException("Secret key for message not found.");
            }
     
            InputStream clear = pbe.getDataStream(secretKey, "BC");
     
            PGPObjectFactory plainFact = new PGPObjectFactory(clear);
     
            Object message = plainFact.nextObject();
     
            // check if data is ZIPed
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