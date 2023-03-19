package rs.urosvesic.authservice.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SaveUserRequest {

    private String id;
    private String username;
    private String email;
    private boolean enabled;

}
