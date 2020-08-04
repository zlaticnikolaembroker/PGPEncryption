package etf.openpgp.indeksi.crypto;

import org.bouncycastle.openpgp.*;

import etf.openpgp.indeksi.front.PasswordVerificator;
import etf.openpgp.indeksi.front.InfoScreen;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;

public class Decryptor {
    private static final int BUFFER_SIZE = 1 << 16; // 64k

    private final KeyRings keyRings;
    private final Verifier verifier;

    public Decryptor(KeyRings keyRings) {
        this.keyRings = keyRings;
        this.verifier = new Verifier(keyRings);
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
    
    public void decryptOrVerifyFile(InputStream in, File outputFile, String signaturePath)
        {
	    	try (InputStream inputStream = PGPUtil.getDecoderStream(in)) {

	            PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(inputStream);
	            PGPEncryptedDataList encryptedDataList = null;
	     
	            Object pgpObject = pgpObjectFactory.nextObject();

	            // ako je prvi objekat marker, pomeramo se na sledeci
				if (pgpObject instanceof PGPMarker) {
					pgpObject = pgpObjectFactory.nextObject();
				}

	            if (pgpObject instanceof PGPEncryptedDataList) {
	                encryptedDataList = (PGPEncryptedDataList) pgpObject;
	            }
	            if (encryptedDataList == null) {
	            	// nema enkriptovanih podataka, idemo na verifikaciju
					if (pgpObject instanceof PGPCompressedData) {
						//ovo ne bi nikad trebalo da se desi, jer je ili potpisan ili enkriptovan podatak.
						System.out.println("compressed data");
					}
					if (pgpObject instanceof PGPSignatureList) {
						verifier.verifySignature((PGPSignatureList) pgpObject, signaturePath);
					}
					return;
				}

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
	    			if (pgpFact == null) {
	    				message = plainFact.nextObject();
	    			} else {
	    				message = pgpFact.nextObject();
	    			}
	    		}
	     
	            if (message instanceof  PGPLiteralData) {
	                PGPLiteralData ld = (PGPLiteralData) message;
	     
	                InputStream unc = ld.getInputStream();
	                
	                byte[] buffer = new byte[BUFFER_SIZE];
	                int len;
	                OutputStream out = new FileOutputStream(outputFile);
	                while ((len = unc.read(buffer)) > 0) {
	                	out.write(buffer, 0, len);
					}
	                
	                String label = "File successfully decrypted.";
	                if (userId != null) {
	                	label += " Signed by: " + userId + ".";
	                }
	                InfoScreen successScreen = new InfoScreen("File successfully decrypted", label);
	                successScreen.showAndWait();
	            }
	        } catch(Exception e) {
                InfoScreen successScreen = new InfoScreen("Something went wrong", e.getMessage());
	            successScreen.showAndWait();
                e.printStackTrace();
            }
        }
}