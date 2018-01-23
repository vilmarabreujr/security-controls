package controls.openid;

import org.apache.amber.oauth2.client.OAuthClient;
import org.apache.amber.oauth2.client.URLConnectionClient;
import org.apache.amber.oauth2.client.request.OAuthClientRequest;
import org.apache.amber.oauth2.client.response.OAuthClientResponse;
import org.apache.amber.oauth2.common.exception.OAuthProblemException;
import org.apache.amber.oauth2.common.exception.OAuthSystemException;
import org.apache.amber.oauth2.common.message.types.GrantType;

import util.AuthProperties;

public class AuthorizationService {
    
    private static final String ACCESS_TOKEN_PARAM = "access_token";
    private static final String ID_TOKEN_PARAM = "id_token";
    private String idToken;
    /**
     * 
     * @param consumerKey
     * @param authToken
     * @param callbackUri
     * @param clientSecret
     * @return the given token by wso2
     * @throws OAuthSystemException
     * @throws OAuthProblemException
     */
    
    public String getCurrentIDToken()
    {
    	return idToken;
    }
    
    public String requestAccessToken(String authToken, String callbackUri) throws OAuthSystemException, 
                                                                                        OAuthProblemException {

        OAuthClientRequest accessRequest = getRequest(authToken, callbackUri);
        OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
        OAuthClientResponse oAuthResponse = oAuthClient.accessToken(accessRequest);        
        String accessToken = oAuthResponse.getParam(ACCESS_TOKEN_PARAM);
        System.out.println(oAuthResponse.toString());
        System.out.println(oAuthResponse.getParam("scope"));
        idToken = oAuthResponse.getParam(ID_TOKEN_PARAM);

        return accessToken;
    }

    /**
     * 
     * @param consumerKey
     * @param authToken
     * @param callbackUri
     * @param clientSecret
     * @return configured request
     * @throws OAuthSystemException
     */
    private OAuthClientRequest getRequest(String authToken, String callbackUri) throws OAuthSystemException {
        AuthProperties props = AuthProperties.inst();

        return OAuthClientRequest.tokenLocation(props.getTokenEndpoint())
                .setGrantType(GrantType.AUTHORIZATION_CODE)
                .setClientId(props.getConsumerKey())
                .setClientSecret(props.getConsumerSecret())
                .setRedirectURI(callbackUri)
                .setCode(authToken)
                .buildBodyMessage();
    }

}
