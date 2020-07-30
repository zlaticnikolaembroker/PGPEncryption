package etf.openpgp.indeksi.front;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

public class KeyColumn {
	
	//not sure if we need password to be stored, since we will need to use method from keyRings which will need password(passphrase) to be listed as parameters
	private String email, name, password;
	private long keyId;
	private boolean isPublic, isMasterKey;
	private PGPPublicKey publicKey;
	private PGPSecretKey secretKey;
	
	public KeyColumn(String _email, String _name, String _password, long _keyId, boolean _isPublic, boolean _isMasterKey, PGPPublicKey _publicKey, PGPSecretKey _secretKey) {
		this.email = _email;
		this.name = _name;
		this.password = _password;
		this.keyId = _keyId;
		this.isPublic = _isPublic;
		this.isMasterKey = _isMasterKey;
		this.publicKey = _publicKey;
		this.secretKey = _secretKey;
	}
	
	public String getEmail() {
		return email;
	}
	
	public String getName() {
		return name;
	}
	
	public String getUserId() {
		return name + " <" + email + ">";
	}
	
	public String getPassword() {
		return this.password;
	}
	
	public long getKeyId() {
		return keyId;
	}
	
	public boolean getIsPublic() {
		return this.isPublic;
	}
	
	public boolean getIsMasterKey() {
		return this.isMasterKey;
	}
	
	public PGPPublicKey getPublicKey() {
		return this.publicKey;
	}
	
	public PGPSecretKey getSecretKey() {
		return this.secretKey;
	}
	
	public void setIsMasterKey(boolean newValue) {
		this.isMasterKey = newValue;
	}

	public void setEmail(String newMail) {
		this.email = newMail;
	}
	
	public void setName(String newName) {
		this.name = newName;
	}
	
	public void setPassword(String newPassword) {
		this.password = newPassword;
	}
	
	public void setKeyId(long newKeyId) {
		this.keyId = newKeyId;
	}
	
	public void setIsPublic(boolean newIsPublic) {
		this.isPublic = newIsPublic;
	}
	
	public void setPublicKey(PGPPublicKey newPublicKey) {
		this.publicKey = newPublicKey;
	}
	
	public void setSecretkey(PGPSecretKey newSecretKey) {
		this.secretKey = newSecretKey;
	}
	
}
