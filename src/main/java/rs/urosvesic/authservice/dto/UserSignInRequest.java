package rs.urosvesic.authservice.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserSignInRequest {

    @NotEmpty(message = "Username should not be empty.")
    private String username;
    @NotBlank(message = "Password is required")
    private String password;
}
