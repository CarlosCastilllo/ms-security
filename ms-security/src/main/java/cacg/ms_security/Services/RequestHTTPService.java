package cacg.ms_security.Services;

import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
public class RequestHTTPService {

    private final RestTemplate restTemplate = new RestTemplate();

    /**
     * Envía una solicitud POST a una URL externa.
     *
     * @param url     destino de la solicitud
     * @param body    cuerpo del request (JSON, Map, DTO, etc.)
     * @param headers headers adicionales (puede ser null)
     * @return ResponseEntity con el resultado de la llamada
     */
    public ResponseEntity<String> sendPost(String url, Object body, Map<String, String> headers) {
        try {
            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.setContentType(MediaType.APPLICATION_JSON);

            if (headers != null) {
                headers.forEach(httpHeaders::set);
            }

            HttpEntity<Object> requestEntity = new HttpEntity<>(body, httpHeaders);
            return restTemplate.exchange(url, HttpMethod.POST, requestEntity, String.class);

        } catch (RestClientException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\"error\":\"Error en la solicitud POST: " + e.getMessage() + "\"}");
        }
    }

    /**
     * Envía una solicitud GET a una URL externa.
     */
    public ResponseEntity<String> sendGet(String url, Map<String, String> headers) {
        try {
            HttpHeaders httpHeaders = new HttpHeaders();
            if (headers != null) {
                headers.forEach(httpHeaders::set);
            }

            HttpEntity<Void> requestEntity = new HttpEntity<>(httpHeaders);
            return restTemplate.exchange(url, HttpMethod.GET, requestEntity, String.class);

        } catch (RestClientException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\"error\":\"Error en la solicitud GET: " + e.getMessage() + "\"}");
        }
    }
}
