package etf.openpgp.indeksi.front;

public class KeyColumn {
	
	private String email, name;
	private long keyId;
	private boolean isPublic, isMasterKey;
	
	public KeyColumn(String _email, String _name, long _keyId, boolean _isPublic, boolean _isMasterKey) {
		this.email = _email;
		this.name = _name;
		this.keyId = _keyId;
		this.isPublic = _isPublic;
		this.isMasterKey = _isMasterKey;
	}
	
	public String getEmail() {
		return email;
	}
	
	public String getName() {
		return name;
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
	
	public void setIsMasterKey(boolean newValue) {
		this.isMasterKey = newValue;
	}

	public void setEmail(String newMail) {
		this.email = newMail;
	}
	
	public void setName(String newName) {
		this.name = newName;
	}
	
	public void setKeyId(long newKeyId) {
		this.keyId = newKeyId;
	}
	
	public void setIsPublic(boolean newIsPublic) {
		this.isPublic = newIsPublic;
	}
}
