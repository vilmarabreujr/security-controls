package controls.response;

import java.io.Serializable;

public class AuthorizationResponse implements Serializable {

    private static final long serialVersionUID = 6204577444828537572L;

    private String accessToken;
    private String idToken;

    public AuthorizationResponse(String accessToken, String idToken) {
        setAccessToken(accessToken);
        setIDToken(idToken);
    }

    public AuthorizationResponse() {
        this("", "");
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getIDToken() {
        return idToken;
    }

    public void setIDToken(String idToken) {
        this.idToken = idToken;
    }
}
