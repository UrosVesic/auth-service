package rs.urosvesic.authservice.dto;


import javax.validation.constraints.NotBlank;

public record CustomResetPasswordRequest(@NotBlank(message = "Username is required") String username,
                                         @NotBlank(message = "Code is required") String confirmationCode,
                                         @NotBlank(message = "Password is required") String password)
{
}
