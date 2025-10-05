package cacg.ms_security.Controllers;

import cacg.ms_security.Models.Permission;
import cacg.ms_security.Models.Session;
import cacg.ms_security.Models.User;
import cacg.ms_security.Models.UserLogin;
import cacg.ms_security.Repositories.UserRepository;
import cacg.ms_security.Repositories.SessionRepository;
import cacg.ms_security.Services.EncryptionService;
import cacg.ms_security.Services.JwtService;
import cacg.ms_security.Services.NotificationService;
import cacg.ms_security.Services.ValidatorsService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;


import java.io.IOException;
import java.util.Date;
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
    @Autowired
    private NotificationService theNotificationService;
    @Autowired
    private SessionRepository theSessionRepository;

    private ValidatorsService theValidatorsService;

    @Value("${jwt.expiration}")
    private Long expiration;

    @PostMapping("permissions-validation")
    public boolean permissionsValidation(final HttpServletRequest request,
                                         @RequestBody Permission thePermission) {
        boolean success=this.theValidatorsService.validationRolePermission(request,thePermission.getUrl(),thePermission.getMethod());
        return success;
    }

    @PostMapping("login")
    public HashMap<String,Object> login(@RequestBody UserLogin userLogin,
                                        final HttpServletResponse response)throws IOException {
        HashMap<String,Object> theResponse=new HashMap<>();
        User theActualUser=this.theUserRepository.getUserByEmail(userLogin.getEmail());
        boolean existUser= theActualUser!=null;
        String contraseñaEncriptada=theEncryptionService.convertSHA256(userLogin.getPassword());
        String contraseñaActualEnBD= theActualUser.getPassword();
        if (existUser == false) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        }
        if(contraseñaActualEnBD .equals( contraseñaEncriptada) == false) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        }
        //llamar el servicio que genere el codigo y generar el codigo
        //despues guardar el codigo en el code2fa de la sesion del usuario
        // enviar codigo

        String codigo = String.format("%06d", (int)(Math.random()*999999));

        // Crear sesión
        Session session = new Session();
        session.setCode2FA(codigo);
        session.setExpiration(new Date(System.currentTimeMillis() + expiration));
        session.setUser(theActualUser); // ya la asocias aquí
        this.theSessionRepository.save(session);
        String email = theActualUser.getEmail();
        String subjet = "Codigo de autenticacion";
        String nameUser = theActualUser.getName();


        //enviando correo con texto Html
        String contenidoHtml =String.format("<html><body><h1>Hola %s</h1><p>Este es tu codigo %s </p></body></html>",nameUser, codigo);
        theNotificationService.sendHTMLEmail(email,subjet,contenidoHtml);
        theResponse.put("message", "Se envió el código a tu correo");
        theResponse.put("sessionId", session.get_id());
        return  theResponse;

    }


    @PostMapping("validate2fa")
    public HashMap<String,Object> validate2fa(@RequestBody HashMap<String,String> data,
                                              final HttpServletResponse response)throws IOException {
        HashMap<String,Object> theResponse=new HashMap<>();

        String email = data.get("email");
        String code2FA = data.get("code2FA");
        String sessionId = data.get("sessionId");

        User theActualUser = this.theUserRepository.getUserByEmail(email);

        if (theActualUser == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Usuario no encontrado");
            return theResponse;
        }

        Session session = this.theSessionRepository.findById(sessionId).orElse(null);

        if (session == null || session.getUser() == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Sesión inválida");
            return theResponse;
        }

        if (session.getUser().get_id().equals(theActualUser.get_id())
                && session.getCode2FA().equals(code2FA)
                && session.getExpiration().after(new Date())) {

            String token = theJwtService.generateToken(theActualUser);
            session.setToken(token);
            this.theSessionRepository.save(session);

            theActualUser.setPassword(""); // no exponer password

            theResponse.put("token", token);
            theResponse.put("user", theActualUser);
            return theResponse;
        } else {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Código inválido o expirado");
            return theResponse;
        }
    }


    @PostMapping("validate2faantiguo")
    public HashMap<String,Object>validate2fa(@RequestBody UserLogin userLogin,
                                        final HttpServletResponse response)throws IOException {
        HashMap<String,Object> theResponse=new HashMap<>();
        String token="";
        User theActualUser=this.theUserRepository.getUserByEmail(userLogin.getEmail());
        if(theActualUser!=null &&
                theActualUser.getPassword().equals(theEncryptionService.convertSHA256(userLogin.getPassword()))){
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
