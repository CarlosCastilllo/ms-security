package cacg.ms_security.Services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class NotificationService {

    @Value("${ms.URLnotification}")
    private String URLnotification; // Ejemplo: http://localhost:5000

    @Value("${email.sender}")
    private String sender;

    private final RequestHTTPService requestHTTPService;

    public NotificationService(RequestHTTPService requestHTTPService) {
        this.requestHTTPService = requestHTTPService;
    }

    /**
     * Envía un correo plano (texto) al microservicio de notificaciones.
     */
    public ResponseEntity<String> send2FAemail( String to, String subject, String message) {
        String endpoint = URLnotification + "/send/plain";

        Map<String, Object> body = new HashMap<>();
        body.put("sender", sender);
        body.put("to", to);
        body.put("subject", subject);
        body.put("message", message);

        return requestHTTPService.sendPost(endpoint, body, null);
    }

    /**
     * Envía un correo con contenido HTML al microservicio de notificaciones.
     */
    public ResponseEntity<String> sendHTMLEmail( String to, String subject, String htmlContent) {
        String endpoint = URLnotification + "/send/html";

        Map<String, Object> body = new HashMap<>();
        body.put("sender", sender);
        body.put("to", to);
        body.put("subject", subject);
        body.put("html_content", htmlContent);

        return requestHTTPService.sendPost(endpoint, body, null);
    }
}

