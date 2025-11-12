package cacg.ms_security.Services;

import cacg.ms_security.Models.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {
    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Long expiration;

    private Key secretKey;
    private SignatureAlgorithm algorithm;

    @PostConstruct
    public void init() {
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        int keyLength = keyBytes.length;

        System.out.println("🔑 Inicializando JWT Service...");
        System.out.println("📏 Longitud de la clave: " + keyLength + " bytes");

        if (keyLength >= 64) {
            // Clave suficientemente larga para HS512 (512 bits = 64 bytes)
            this.algorithm = SignatureAlgorithm.HS512;
            this.secretKey = Keys.hmacShaKeyFor(keyBytes);
            System.out.println("✅ Usando algoritmo HS512");
        } else if (keyLength >= 32) {
            // Clave suficiente para HS256 (256 bits = 32 bytes)
            this.algorithm = SignatureAlgorithm.HS256;
            this.secretKey = Keys.hmacShaKeyFor(keyBytes);
            System.out.println("⚠️ Clave corta, usando algoritmo HS256");
            System.out.println("💡 Recomendación: Use una clave de al menos 64 caracteres para HS512");
        } else {
            // Clave demasiado corta
            throw new IllegalArgumentException(
                    "❌ ERROR CRÍTICO: jwt.secret debe tener al menos 32 caracteres. " +
                            "Longitud actual: " + keyLength + " bytes. " +
                            "Por favor, actualice su application.properties con una clave más larga."
            );
        }
    }

    public String generateToken(User theUser) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);
        Map<String, Object> claims = new HashMap<>();
        claims.put("_id", theUser.get_id());
        claims.put("name", theUser.getName());
        claims.put("email", theUser.getEmail());

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(theUser.getName())
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(secretKey, algorithm)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);

            Date now = new Date();
            if (claimsJws.getBody().getExpiration().before(now)) {
                System.out.println("❌ Token expirado");
                return false;
            }

            System.out.println("✅ Token válido");
            return true;
        } catch (SignatureException ex) {
            System.err.println("❌ Firma del token inválida: " + ex.getMessage());
            System.err.println("💡 Posibles causas:");
            System.err.println("   1. La clave jwt.secret cambió después de generar el token");
            System.err.println("   2. El token fue generado por otra aplicación");
            System.err.println("   3. El token fue modificado manualmente");
            return false;
        } catch (Exception e) {
            System.err.println("❌ Error validando token: " + e.getMessage());
            return false;
        }
    }

    public User getUserFromToken(String token) {
        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);

            Claims claims = claimsJws.getBody();

            User user = new User();
            user.set_id((String) claims.get("_id"));
            user.setName((String) claims.get("name"));
            user.setEmail((String) claims.get("email"));
            return user;
        } catch (Exception e) {
            System.err.println("❌ Error extrayendo usuario del token: " + e.getMessage());
            return null;
        }
    }
}
