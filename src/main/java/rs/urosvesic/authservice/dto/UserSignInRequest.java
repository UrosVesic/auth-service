package rs.urosvesic.authservice.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Pattern;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserSignInRequest {

    @NotEmpty(message = "Username should not be empty.")
    private String username;

    @Pattern(regexp = "^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%]).{8,20}$",
            message = "Password should contain: at least one numeric character, at least one lowercase character, " +
                    "at least one uppercase character, at least one special symbol among @#$% and length should be between 8 and 20.")
    private String password;
}
