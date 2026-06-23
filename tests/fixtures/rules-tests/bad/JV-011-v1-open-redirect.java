import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.servlet.ModelAndView;
import jakarta.servlet.http.HttpServletResponse;

public class RedirectController {

    public String redirectOld(@RequestParam String url) {
        return "redirect:" + url;
    }

    public RedirectView redirectView(@RequestParam String target) {
        return new RedirectView(target);
    }

    public ModelAndView redirectModel(@RequestParam String page) {
        ModelAndView mav = new ModelAndView();
        mav.setViewName("redirect:" + page);
        return mav;
    }

    public void sendRedirect(HttpServletResponse response, @RequestParam String url) throws Exception {
        response.sendRedirect(url);
    }
}
