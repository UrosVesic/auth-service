package rs.urosvesic.authservice.dto;

import lombok.Data;

@Data
public class UserSignInResponse {

    private String idToken;
    private String refreshToken;
    private String tokenType;
    private Integer expiresIn;
    private String accessToken;
    private boolean isAdmin;
    private String username;
}
