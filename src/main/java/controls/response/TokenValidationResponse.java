package controls.response;

import java.io.Serializable;

public class TokenValidationResponse implements Serializable {

    private static final long serialVersionUID = 4308448426312365524L;

    private boolean isTokenValid;
    private String subject;

    public TokenValidationResponse() {
        setTokenValid(false);
        setSubject("invalid");
    }

    public TokenValidationResponse(boolean isTokenValid, String subject) {
        setTokenValid(isTokenValid);
        setSubject(subject);
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
}
