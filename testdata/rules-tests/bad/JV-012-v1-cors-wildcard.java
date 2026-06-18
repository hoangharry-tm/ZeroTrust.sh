import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

public class CorsConfig {

    @CrossOrigin(origins = "*")
    public String insecureEndpoint() {
        return "data";
    }

    @CrossOrigin("*")
    public String insecureShort() {
        return "data";
    }

    public WebMvcConfigurer corsConfigurer() {
        return registry -> registry.addMapping("/**")
            .allowedOrigins("*");
    }
}
