package controls.response;

import java.io.Serializable;

public class TokenValidationResponse implements Serializable {

    private static final long serialVersionUID = 4308448426312365524L;

    private boolean isTokenValid;
    private String subject;
    private String scope;

    public TokenValidationResponse() {
        setTokenValid(false);
        setSubject("invalid");
        setScope("invalid");
    }

    public TokenValidationResponse(boolean isTokenValid, String subject, String scope) {
        setTokenValid(isTokenValid);
        setSubject(subject);
        setScope(scope);
    }

    public boolean isTokenValid() {
        return isTokenValid;
    }

    public void setTokenValid(boolean isTokenValid) {
        this.isTokenValid = isTokenValid;
    }

	public String getSubject() {
		return subject;
	}

	public void setSubject(String subject) {
		this.subject = subject;
	}
	
	public String getScope() {
		return scope;
	}

	public void setScope(String scope) {
		this.scope = scope;
	}
}
