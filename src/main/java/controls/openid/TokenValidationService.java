package controls.openid;

import java.rmi.RemoteException;

import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.transport.http.HTTPConstants;
import org.wso2.carbon.identity.oauth2.stub.OAuth2TokenValidationServiceStub;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationRequestDTO_OAuth2AccessToken;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.utils.CarbonUtils;

import util.AuthProperties;

public class TokenValidationService {
    
    private static final int TIMEOUT_IN_MILLIS = 15 * 1000;
    private String subject = "";
    private AuthProperties props;
    public TokenValidationService(AuthProperties _props)
    {
    	this.props = _props;
    }
    /**
     * 
     * @param accessToken
     * @return token is valid
     * @throws RemoteException
     */
    public boolean isTokenValid(String accessToken) throws RemoteException {
        OAuth2TokenValidationResponseDTO resp = getTokenValidation(accessToken);
        this.subject = resp.getAuthorizedUser();
        return resp.getValid();
    }
    
    public String getSubject()
    {
    	return subject;
    }
    
    /**
     * 
     * @param accessToken
     * @return
     * @throws AxisFault
     * @throws RemoteException
     */
    public OAuth2TokenValidationResponseDTO getTokenValidation(String accessToken) throws AxisFault, RemoteException {
        OAuth2TokenValidationRequestDTO oauthReq = new OAuth2TokenValidationRequestDTO();
        oauthReq.setAccessToken(getOAuthToken(accessToken));
        return getValidationService().validate(oauthReq);        
    }

    /**
     * 
     * @param accessToken
     * @return Token object provided by carbon API
     */
    private OAuth2TokenValidationRequestDTO_OAuth2AccessToken getOAuthToken(String accessToken) {
        OAuth2TokenValidationRequestDTO_OAuth2AccessToken oauthToken;
        oauthToken = new OAuth2TokenValidationRequestDTO_OAuth2AccessToken();
        oauthToken.setIdentifier(accessToken);
        oauthToken.setTokenType("bearer");
        return oauthToken;
    }

    /**
     * 
     * @return validation service ready for use
     * @throws AxisFault
     */
    private OAuth2TokenValidationServiceStub getValidationService() throws AxisFault {
        String serviceURL = props.getTokenValidationEndpoint();
        OAuth2TokenValidationServiceStub stub = new OAuth2TokenValidationServiceStub(null, serviceURL);
        return setupValidationService(stub);
    }

    /**
     * 
     * @param stub
     * @return receives a non prepared stub and set up it
     */
    private OAuth2TokenValidationServiceStub setupValidationService(OAuth2TokenValidationServiceStub stub) {
        ServiceClient client = stub._getServiceClient();
        Options options = client.getOptions();

        CarbonUtils.setBasicAccessSecurityHeaders(props.getWso2User(), props.getWso2Password(), true, client);

        options.setTimeOutInMilliSeconds(TIMEOUT_IN_MILLIS);
        options.setProperty(HTTPConstants.SO_TIMEOUT, TIMEOUT_IN_MILLIS);
        options.setProperty(HTTPConstants.CONNECTION_TIMEOUT, TIMEOUT_IN_MILLIS);
        options.setCallTransportCleanup(true);
        options.setManageSession(true);

        return stub;
    }

}
