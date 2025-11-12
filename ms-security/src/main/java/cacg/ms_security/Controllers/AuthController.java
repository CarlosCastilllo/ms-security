package cacg.ms_security.Controllers;

import cacg.ms_security.Models.User;
import cacg.ms_security.Repositories.UserRepository;
import com.google.firebase.auth.*;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@CrossOrigin
@RestController
@RequestMapping("/api/public/auth")
public class AuthController {

    private final UserRepository userRepository;


    public AuthController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }


    @PostMapping("/firebase-login")
    public FirebaseUserResponse loginConFirebase(@RequestHeader("Authorization") String authHeader) throws FirebaseAuthException {
        String token = authHeader.replace("Bearer ", "");


        // 1. Verificar token de Firebase
        FirebaseToken decodedToken = FirebaseAuth.getInstance().verifyIdToken(token);

        // Extraer datos
        String uid = decodedToken.getUid();
        String email = decodedToken.getEmail();
        String name = (String) decodedToken.getClaims().getOrDefault("name", "");
        String picture = (String) decodedToken.getClaims().getOrDefault("picture", "");

        // Obtener el proveedor desde el claim "firebase.sign_in_provider" del ID token
        String provider = "";
        Object firebaseClaim = decodedToken.getClaims().get("firebase");
        if (firebaseClaim instanceof Map) {
            Map<?, ?> firebaseMap = (Map<?, ?>) firebaseClaim;
            Object signInProvider = firebaseMap.get("sign_in_provider");
            if (signInProvider != null) {
                provider = signInProvider.toString();
            }
        }

        // 2. Buscar usuario en tu BD
        Optional<User> existingUser = userRepository.findAll()
                .stream()
                .filter(u -> u.getEmail().equals(email))
                .findFirst();

        User user;
        if (existingUser.isPresent()) {
            user = existingUser.get();
        } else {
            // 3. Crear solo con los datos necesarios
            user = new User();
            user.setName(name != null && !name.isEmpty() ? name : email);
            user.setEmail(email);
            user.setPassword(""); // porque Firebase maneja la autenticación
            user = userRepository.save(user);
        }

        // 4. Retornar todo lo de Firebase + los datos del usuario en tu BD
        return new FirebaseUserResponse(uid, email, name, picture, provider, user.get_id());
    }

    // DTO para devolver al frontend
    public record FirebaseUserResponse(
            String uid,
            String email,
            String name,
            String picture,
            String provider,
            String systemUserId // id en tu BD
    ) {}
}