package etf.openpgp.indeksi.front;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

public class KeyColumn {
	
	//not sure if we need password to be stored, since we will need to use method from keyRings which will need password(passphrase) to be listed as parameters
	private String email, name, password, keyId;
	private long originalKeyId;
	private boolean isPublic;
	private PGPPublicKey publicKey;
	private PGPSecretKey secretKey;
	
	public KeyColumn(String _email, String _name, String _password, long _keyId, boolean _isPublic, PGPPublicKey _publicKey, PGPSecretKey _secretKey) {
		this.email = _email;
		this.name = _name;
		this.password = _password;
		this.originalKeyId = _keyId;
		this.keyId = Long.toHexString(_keyId).toUpperCase().substring(0,4) + " " + Long.toHexString(_keyId).toUpperCase().substring(4, 8) + " " + Long.toHexString(_keyId).toUpperCase().substring(8, 12) + " " + Long.toHexString(_keyId).toUpperCase().substring(12);
		this.isPublic = _isPublic;
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
	
	public long getOriginalKeyId() {
		return this.originalKeyId;
	}
	
	public String getKeyId() {
		return keyId;
	}
	
	public boolean getIsPublic() {
		return this.isPublic;
	}
	
	
	public PGPPublicKey getPublicKey() {
		return this.publicKey;
	}
	
	public PGPSecretKey getSecretKey() {
		return this.secretKey;
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
		this.keyId = Long.toHexString(newKeyId);
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
