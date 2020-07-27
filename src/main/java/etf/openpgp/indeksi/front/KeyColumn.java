package etf.openpgp.indeksi.front;

public class KeyColumn {
	
	private String email, name;
	private long keyId;
	private boolean isPublic;
	
	public KeyColumn(String _email, String _name, long _keyId, boolean _isPublic) {
		this.email = _email;
		this.name = _name;
		this.keyId = _keyId;
		this.isPublic = _isPublic;
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
