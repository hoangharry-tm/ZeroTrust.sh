import org.springframework.web.servlet.view.RedirectView;
import java.util.Set;

public class SafeRedirectController {

    private static final Set<String> ALLOWED_REDIRECTS = Set.of("/dashboard", "/profile", "/settings");

    public RedirectView safeRedirect(@RequestParam String page) {
        if (!ALLOWED_REDIRECTS.contains(page)) {
            return new RedirectView("/");
        }
        return new RedirectView(page);
    }

    public String safeView(@RequestParam String view) {
        if (!ALLOWED_REDIRECTS.contains(view)) {
            return "redirect:/";
        }
        return "redirect:" + view;
    }
}
