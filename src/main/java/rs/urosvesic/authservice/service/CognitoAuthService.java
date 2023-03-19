package rs.urosvesic.authservice.service;


import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import rs.urosvesic.authservice.client.UserClient;
import rs.urosvesic.authservice.dto.*;
import rs.urosvesic.authservice.exception.ApplicationException;
import software.amazon.awssdk.auth.credentials.AnonymousCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import javax.annotation.PostConstruct;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Log4j2
@Service
@RequiredArgsConstructor
public class CognitoAuthService {
    @Value("${aws.cognito.clientId}")
    private String clientId;
    @Value("${aws.cognito.clientSecret}")
    private String clientSecret;
    @Value("${aws.cognito.user-pool-id}")
    private String userPoolId;

    @Value("${aws.access-key}")
    private String accessKey;

    @Value("${aws.secret-key}")
    private String secretKey;
    private CognitoIdentityProviderClient cognitoIdentityProviderClient;
    private CognitoIdentityProviderClient client2;

    private final UserClient userClient;




    @PostConstruct
    public void init() {

        // initializing user cognito client
        AnonymousCredentialsProvider anonymousCredentialsProvider = AnonymousCredentialsProvider.create();
        cognitoIdentityProviderClient = CognitoIdentityProviderClient.builder()
                .credentialsProvider(anonymousCredentialsProvider)
                .region(Region.US_EAST_1)
                .build();

        AwsCredentials awsCreds = AwsBasicCredentials.create(accessKey,secretKey);
        StaticCredentialsProvider staticCredentialsProvider = StaticCredentialsProvider.create(awsCreds);

         client2 = CognitoIdentityProviderClient.builder()
                .credentialsProvider(staticCredentialsProvider)
                .region(Region.US_EAST_1)
                .build();
    }

    public void signUp(UserSignUpRequest request){
        log.info("Method start signUp");
        try {
            List<AttributeType> attributeTypes = List.of(AttributeType.builder()
                    .name("email")
                    .value(request.getEmail())
                    .build());
            SignUpRequest signUpRequest = SignUpRequest.builder()
                    .clientId(clientId)
                    .username(request.getUsername())
                    .password(request.getPassword())
                    .secretHash(CognitoAuthUtil
                            .calculateSecretHash(clientId, clientSecret, request.getUsername()))
                    .userAttributes(attributeTypes)
                    .build();

            SignUpResponse signUpResponse = cognitoIdentityProviderClient.signUp(signUpRequest);
            AdminAddUserToGroupRequest addUserToGroupRequest = AdminAddUserToGroupRequest
                    .builder()
                    .groupName("user")
                    .userPoolId(userPoolId)
                    .username(request.getUsername())
                    .build();

            client2.adminAddUserToGroup(addUserToGroupRequest);

        } catch (CognitoIdentityProviderException ex) {
            log.error(ex.getMessage());
            throw new ApplicationException(ex.getMessage());
        }
    }


    public void forgotPassword(final CustomForgotPasswordRequest request) {
        try {
            /*UserDto user = userClient.findUser(request.username(), UserUtil.getToken());
            if(!user.getEmail().equals(request.email())) {
                throw new RuntimeException(String.format("Provided email address does not match with %s's email address"
                        , request.username()));
            }*/
            final ForgotPasswordRequest forgotPasswordRequest = ForgotPasswordRequest.builder()
                    .secretHash(CognitoAuthUtil
                            .calculateSecretHash(clientId, clientSecret, request.username()))
                    .clientId(clientId)
                    .username(request.username())
                    .build();
            cognitoIdentityProviderClient.forgotPassword(forgotPasswordRequest);
        }
        catch (final Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    public void resetPassword(final CustomResetPasswordRequest request) {
        try {
            final ConfirmForgotPasswordRequest confirmForgotPasswordRequest = ConfirmForgotPasswordRequest.builder()
                    .secretHash(CognitoAuthUtil
                            .calculateSecretHash(clientId, clientSecret, request.username()))
                    .clientId(clientId)
                    .username(request.username())
                    .confirmationCode(request.confirmationCode())
                    .password(request.password())
                    .build();
            cognitoIdentityProviderClient.confirmForgotPassword(confirmForgotPasswordRequest);
        }
        catch (final Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    public UserSignInResponse signIn(UserSignInRequest request) throws ApplicationException {
        log.info("Method start login");
        try {
            Map<String, String> authParams = new HashMap<>();
            authParams.put("USERNAME", request.getUsername());
            authParams.put("PASSWORD", request.getPassword());
            authParams.put("SECRET_HASH",
                    CognitoAuthUtil.calculateSecretHash(clientId, clientSecret, request.getUsername()));
            authParams.put("SRP_A", CognitoAuthUtil.getA().toString(16));
            InitiateAuthRequest initiateAuthRequest = InitiateAuthRequest.builder()
                    .authFlow(AuthFlowType.USER_PASSWORD_AUTH)
                    .authParameters(authParams)
                    .clientId(clientId)
                    .build();
            InitiateAuthResponse authResponse = cognitoIdentityProviderClient.initiateAuth(initiateAuthRequest);

            if (authResponse != null
                    && authResponse.challengeName() != null
                    && authResponse.challengeNameAsString() != null) {
                throw new ApplicationException(authResponse.challengeNameAsString());
            }
            if (authResponse != null && authResponse.authenticationResult() != null) {
                UserSignInResponse userSignInResponseData = new UserSignInResponse();
                userSignInResponseData.setAccessToken(authResponse.authenticationResult().accessToken());
                userSignInResponseData.setExpiresIn(authResponse.authenticationResult().expiresIn());
                userSignInResponseData.setIdToken(authResponse.authenticationResult().idToken());
                userSignInResponseData.setRefreshToken(authResponse.authenticationResult().refreshToken());
                userSignInResponseData.setTokenType(authResponse.authenticationResult().tokenType());
                userSignInResponseData.setUsername(request.getUsername());

                final DecodedJWT decodedIdToken = JWT.decode(userSignInResponseData.getIdToken());
                List<String> authorities = decodedIdToken.getClaim("cognito:groups").asList(String.class);
                userSignInResponseData.setAdmin(authorities.contains("admin"));

                saveUser(userSignInResponseData.getIdToken(),userSignInResponseData.getAccessToken());

                return userSignInResponseData;
            }
        } catch (CognitoIdentityProviderException | NoSuchAlgorithmException ex) {
            log.error(ex.getMessage());
            throw new ApplicationException(ex.getMessage());
        }
        return null;
    }

    private void saveUser(String idToken, String accessToken) {
        final DecodedJWT decodedIdToken = JWT.decode(idToken);
        final String userId = decodedIdToken.getSubject();
        SaveUserRequest saveUserRequest = new SaveUserRequest(userId,
                decodedIdToken.getClaim("cognito:username").asString(),
                decodedIdToken.getClaim("email").asString(),true);
        userClient.saveUser(saveUserRequest,"Bearer "+accessToken);
    }

    //this method is when user want to sign out, execution is successful but token is not invalid
    public void signOut(String token) throws ApplicationException {
        log.info("Method start logout");
        try {
            GlobalSignOutRequest globalSignOutRequest = GlobalSignOutRequest.builder()
                    .accessToken(token).build();
            cognitoIdentityProviderClient.globalSignOut(globalSignOutRequest);
        } catch (CognitoIdentityProviderException ex) {
            log.error(ex.getMessage());
            throw new ApplicationException(ex.getMessage());
        } finally {
            log.info("Method end logout");
        }
    }

    public RefreshTokenResponse refreshToken(RefreshTokenRequest request) {
        try {
            Map<String, String> authParams = new HashMap<>();
            authParams.put("REFRESH_TOKEN", request.refreshToken());
            authParams.put("SECRET_HASH",
                    CognitoAuthUtil.calculateSecretHash(clientId, clientSecret, request.username()));
            authParams.put("SRP_A", CognitoAuthUtil.getA().toString(16));
            InitiateAuthRequest initiateAuthRequest = InitiateAuthRequest.builder()
                    .authFlow(AuthFlowType.REFRESH_TOKEN_AUTH)
                    .authParameters(authParams)
                    .clientId(clientId)
                    .build();
            InitiateAuthResponse authResponse = cognitoIdentityProviderClient.initiateAuth(initiateAuthRequest);

            if (authResponse != null
                    && authResponse.challengeName() != null
                    && authResponse.challengeNameAsString() != null) {
                throw new ApplicationException(authResponse.challengeNameAsString());
            }
            if (authResponse != null && authResponse.authenticationResult() != null) {
                return new RefreshTokenResponse(
                        authResponse.authenticationResult().accessToken(),
                        authResponse.authenticationResult().idToken()
                );
            }
        } catch (CognitoIdentityProviderException | NoSuchAlgorithmException ex) {
            log.error(ex.getMessage());
            throw new ApplicationException(ex.getMessage());
        }
        return null;
    }

    public void enableUser(String username) {
        AdminEnableUserRequest adminEnableUserRequest = AdminEnableUserRequest.builder()
                .username(username)
                .userPoolId(userPoolId)
                .build();
        client2.adminEnableUser(adminEnableUserRequest);

    }

    public void disableUser(String username) {
        AdminDisableUserRequest adminDisableUserRequest = AdminDisableUserRequest.builder()
                .username(username)
                .userPoolId(userPoolId)
                .build();
        client2.adminDisableUser(adminDisableUserRequest);

    }

    private class CognitoAuthUtil {
        private final static String HMAC_SHA256_ALGORITHM = "HmacSHA256";
        private static final String HEX_N = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                + "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
                + "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
                + "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
                + "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
                + "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
                + "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

        public static String calculateSecretHash(String userClientId, String userSecret, String userName) {
            if (userSecret == null) {
                return null;
            }
            SecretKeySpec signingKey = new SecretKeySpec(
                    userSecret.getBytes(StandardCharsets.UTF_8),
                    HMAC_SHA256_ALGORITHM);
            try {
                Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
                mac.init(signingKey);
                mac.update(userName.getBytes(StandardCharsets.UTF_8));
                return Base64.getEncoder().encodeToString(mac.doFinal(userClientId.getBytes(StandardCharsets.UTF_8)));
            } catch (Exception e) {
                throw new ApplicationException("Error while calculating ");
            }
        }

        public static BigInteger getA() throws NoSuchAlgorithmException {
            BigInteger A;
            BigInteger a;
            do {
                a = new BigInteger(1024, SecureRandom.getInstance("SHA1PRNG"))
                        .mod(new BigInteger(HEX_N, 16));
                A = BigInteger.valueOf(2)
                        .modPow(a, new BigInteger(HEX_N, 16));
            } while (A.mod(new BigInteger(HEX_N, 16)).equals(BigInteger.ZERO));
            return A;
        }
    }


}
