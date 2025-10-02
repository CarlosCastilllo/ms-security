package cacg.ms_security.Controllers;

import cacg.ms_security.Models.Permission;
import cacg.ms_security.Models.User;
import cacg.ms_security.Repositories.UserRepository;
import cacg.ms_security.Services.EncryptionService;
import cacg.ms_security.Services.JwtService;
import cacg.ms_security.Services.ValidatorsService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;


import java.io.IOException;
import java.util.HashMap;

@CrossOrigin
@RestController
@RequestMapping("api/public/security")
public class SecurityController {
    @Autowired
    private UserRepository theUserRepository;
    @Autowired
    private EncryptionService theEncryptionService;
    @Autowired
    private JwtService theJwtService;

    private ValidatorsService theValidatorsService;

    @PostMapping("permissions-validation")
    public boolean permissionsValidation(final HttpServletRequest request,
                                         @RequestBody Permission thePermission) {
        boolean success=this.theValidatorsService.validationRolePermission(request,thePermission.getUrl(),thePermission.getMethod());
        return success;
    }

    @PostMapping("login")
    public HashMap<String,Object> login(@RequestBody User theNewUser,
                                        final HttpServletResponse response)throws IOException {
        HashMap<String,Object> theResponse=new HashMap<>();
        String token="";
        User theActualUser=this.theUserRepository.getUserByEmail(theNewUser.getEmail());
        if(theActualUser!=null &&
           theActualUser.getPassword().equals(theEncryptionService.convertSHA256(theNewUser.getPassword()))){
            token=theJwtService.generateToken(theActualUser);
            theActualUser.setPassword("");
            theResponse.put("token",token);
            theResponse.put("user",theActualUser);
            return theResponse;
        }else{
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return  theResponse;
        }
    }



}
