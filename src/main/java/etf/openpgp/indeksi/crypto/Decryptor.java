package etf.openpgp.indeksi.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;

import etf.openpgp.indeksi.front.PasswordVerificator;
import etf.openpgp.indeksi.front.InfoScreen;

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
    
    private PGPPrivateKey findSecretKey(long keyID)
            throws Exception
        {
     
            PGPSecretKey pgpSecKey = this.keyRings.getSecretKeyRings().getSecretKey(keyID);
     
            if (pgpSecKey == null) {
                return null;
            }

            String password = PasswordVerificator.verify(keyID, this.keyRings);
            
            if (password == null) {
            	throw new Exception("Pass don't match");
            }
     
            return pgpSecKey.extractPrivateKey(password.toCharArray(), "BC");
        }
    
    public void decryptFile(InputStream in, OutputStream out)
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
     
                secretKey = this.findSecretKey(pbe.getKeyID());
            }
     
            if (secretKey == null) {
                throw new IllegalArgumentException("Secret key for message not found.");
            }
     
            InputStream clear = pbe.getDataStream(secretKey, "BC");
     
            PGPObjectFactory plainFact = new PGPObjectFactory(clear);
     
            Object message = plainFact.nextObject();
            PGPObjectFactory pgpFact = null;
            // check if data is ZIP-ed
            if (message instanceof  PGPCompressedData) {
                PGPCompressedData cData = (PGPCompressedData) message;
                pgpFact = new PGPObjectFactory(cData.getDataStream());
                System.out.println("zipped");
                message = pgpFact.nextObject();
            }
            
            PGPOnePassSignature ops = null;
            String userId = null;
            if (message instanceof PGPOnePassSignatureList) {
    			PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) message;
    			ops = p1.get(0);
    			long keyID = ops.getKeyID();
    			PGPPublicKey signerPublicKey = this.keyRings.getPublicKeyRings().getPublicKey(keyID);
    			if (signerPublicKey.getUserIDs().hasNext()) {
    				userId = (String) signerPublicKey.getUserIDs().next();
    			}
    			ops.initVerify(signerPublicKey, "BC");
    			message = pgpFact.nextObject();
    			
    		}
     
            if (message instanceof  PGPLiteralData) {
                PGPLiteralData ld = (PGPLiteralData) message;
     
                InputStream unc = ld.getInputStream();
                int ch;
     
                while ((ch = unc.read()) >= 0) {
                    out.write(ch);
                }
                String label = "File successfully decrypted.";
                if (userId != null) {
                	label += " Sygned by: " + userId + ".";
                }
                InfoScreen successScreen = new InfoScreen("File successfully decrypted", label);
                successScreen.showAndWait();
            }
        }
}