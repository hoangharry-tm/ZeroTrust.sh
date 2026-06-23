import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

public class SafeCorsConfig {

    @CrossOrigin(origins = "https://app.example.com")
    public String secureEndpoint() {
        return "data";
    }

    @CrossOrigin(origins = {"https://app.example.com", "https://admin.example.com"})
    public String multiOrigin() {
        return "data";
    }

    public WebMvcConfigurer corsConfigurer() {
        return registry -> registry.addMapping("/api/**")
            .allowedOrigins("https://app.example.com");
    }
}
