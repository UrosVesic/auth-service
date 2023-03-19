package rs.urosvesic.authservice.controller;

import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rs.urosvesic.authservice.dto.*;
import rs.urosvesic.authservice.service.CognitoAuthService;

import javax.validation.Valid;

@Log4j2
@RestController
@RequestMapping(value = "/api/cognito")
@AllArgsConstructor
public class AuthController {
    private final static String URL_SIGN_UP = "/sign-up";
    private final static String URL_SIGN_IN = "/sign-in";
//    private final static String URI_SIGN_OUT = "/sign-out";
    private final CognitoAuthService authService;


    @PostMapping(value = URL_SIGN_UP)
    public ResponseEntity<Void> signUp(@RequestBody @Valid UserSignUpRequest request) {

        log.info(String.format("CognitoController: SignUp with body: %s)", request.toString()));
        authService.signUp(request);
        return new ResponseEntity<>(HttpStatus.OK);

    }

    @PostMapping(value = "/refresh-token")
    public ResponseEntity<RefreshTokenResponse> refreshToken(@RequestBody @Valid final RefreshTokenRequest request) {
        RefreshTokenResponse refreshTokenResponse = authService.refreshToken(request);
        return new ResponseEntity<>(refreshTokenResponse, HttpStatus.OK);
    }

    @PostMapping(value = "/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestBody @Valid final CustomForgotPasswordRequest request) {
        authService.forgotPassword(request);
        return new ResponseEntity<>("Password reset code successfully sent, check your email address", HttpStatus.OK);
    }

    @PostMapping(value = "/reset-password")
    public ResponseEntity<String> resetPassword(@RequestBody @Valid final CustomResetPasswordRequest request) {
        authService.resetPassword(request);
        return new ResponseEntity<>("Password reset successful", HttpStatus.OK);
    }

    @PostMapping(value = URL_SIGN_IN)
    public ResponseEntity<UserSignInResponse> signIn(@RequestBody @Valid UserSignInRequest request) {

        log.info(String.format("CognitoController: SignIn with username: %s)", request.getUsername()));
        return new ResponseEntity<>(authService.signIn(request), HttpStatus.OK);

    }

//    @SecurityRequirement(name = "Bearer Authentication")
//    @GetMapping(value = URI_SIGN_OUT)
//    public ResponseEntity<String> signOut(Principal principal, @RequestHeader(HttpHeaders.AUTHORIZATION) String bearer) {
//
//        cognitoService.signOut(bearer.substring(7));
//        return new ResponseEntity<>(String.format("User %s is signed out.", principal.getName() ),HttpStatus.OK);
//    }

    @PostMapping("/enable/{username}")
    public ResponseEntity<Void> enableUser(@PathVariable String username){
        authService.enableUser(username);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @PostMapping("/disable/{username}")
    public ResponseEntity<Void> disableUser(@PathVariable String username){
        authService.disableUser(username);
        return new ResponseEntity<>(HttpStatus.OK);
    }



}
