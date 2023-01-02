package rs.urosvesic.authservice.client;


import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import rs.urosvesic.authservice.dto.SaveUserRequest;
@FeignClient(name = "core-client", url = "${CORE_SERVICE_SERVICE_HOST:http://localhost}:8083/api/user")
public interface UserClient {

    @PostMapping
    void saveUser(@RequestBody SaveUserRequest request,
                   @RequestHeader(value = "Authorization") String authorizationHeader);
}
