package restapi.jwt.restcontroller;

import restapi.jwt.payload.response.MessageResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/secure")
public class SecureController {
    @GetMapping("/hello")
    public ResponseEntity<?> hello(){
        return ResponseEntity.ok(new MessageResponse(true, "secure hello request!", null
                , 0L
                ,0
                ,0
                ,0));
    }
}
