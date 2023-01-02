package rs.urosvesic.authservice.controller;

import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rs.urosvesic.authservice.dto.UserSignInRequest;
import rs.urosvesic.authservice.dto.UserSignInResponse;
import rs.urosvesic.authservice.dto.UserSignUpRequest;
import rs.urosvesic.authservice.service.DefaultCognitoService;

import javax.validation.Valid;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Log4j2
@RestController
@RequestMapping(value = "/api/cognito")
@AllArgsConstructor
public class CognitoController {
    private final static String URL_SIGN_UP = "/sign-up";
    private final static String URL_SIGN_IN = "/sign-in";
//    private final static String URL_CONFIRM_SIGN_UP = "/confirm-sign-up";
//    private final static String URI_SIGN_OUT = "/sign-out";
    private final DefaultCognitoService cognitoService;


    @PostMapping(value = URL_SIGN_UP, consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<Void> signUp(@RequestBody @Valid UserSignUpRequest request) {

        log.info(String.format("CognitoController: SignUp with body: %s)", request.toString()));
        cognitoService.signUp(request);
        return new ResponseEntity<>(HttpStatus.OK);

    }

//    @PostMapping(value = URL_CONFIRM_SIGN_UP, consumes = APPLICATION_JSON_VALUE)
//    public ResponseEntity<Void> confirmSignUp(@RequestBody @Valid ConfirmUserSignUpRequest request) {
//        log.info(String.format("CognitoController: ConfirmSignUp with body: %s)", request.toString()));
//        cognitoService.confirmSignUp(request);
//        return new ResponseEntity<>(HttpStatus.OK);
//    }

    @PostMapping(value = URL_SIGN_IN, produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    public ResponseEntity<UserSignInResponse> signIn(@RequestBody @Valid UserSignInRequest request) {

        log.info(String.format("CognitoController: SignIn with username: %s)", request.getUsername()));
        return new ResponseEntity<>(cognitoService.signIn(request), HttpStatus.OK);

    }

//    @SecurityRequirement(name = "Bearer Authentication")
//    @GetMapping(value = URI_SIGN_OUT)
//    public ResponseEntity<String> signOut(Principal principal, @RequestHeader(HttpHeaders.AUTHORIZATION) String bearer) {
//
//        cognitoService.signOut(bearer.substring(7));
//        return new ResponseEntity<>(String.format("User %s is signed out.", principal.getName() ),HttpStatus.OK);
//    }

    @GetMapping(value = "/test")
    public ResponseEntity<String> test() {
        return new ResponseEntity<>("Test",HttpStatus.OK);
    }

}
