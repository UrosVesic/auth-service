package rs.urosvesic.authservice.dto;

import javax.validation.constraints.NotBlank;

public record CustomForgotPasswordRequest(@NotBlank(message = "Username is required") String username,
                                          @NotBlank(message = "Email is required") String email){}
