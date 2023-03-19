package rs.urosvesic.authservice.client;


import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;
import rs.urosvesic.authservice.dto.SaveUserRequest;
import rs.urosvesic.authservice.dto.UserDto;

//@FeignClient(name = "core-client", url = "${CORE_SERVICE_SERVICE_HOST:http://localhost}:8083/api/user")
@FeignClient(name = "CORE-SERVICE")
public interface UserClient {

    @PostMapping("/api/user")
    void saveUser(@RequestBody SaveUserRequest request,
                   @RequestHeader(value = "Authorization") String authorizationHeader);

    @GetMapping("/api/user/{username}")
    UserDto findUser(@PathVariable String username, @RequestHeader(value = "Authorization") String authorizationHeader);
}
