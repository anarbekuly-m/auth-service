package pro.hiking.auth.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;
import pro.hiking.auth.service.JwtService;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtService jwtService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        // 1. Извлекаем данные пользователя из Google/Facebook
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");

        // 2. Генерируем твой внутренний JWT токен
        String token = jwtService.generateToken(email);

        // 3. Формируем URL для редиректа в мобильное приложение
        // Схема: shynapp://
        // Хост: login-callback
        String targetUrl = UriComponentsBuilder.fromUriString("shynapp://login-callback")
                .queryParam("token", token)
                .build()
                .encode()
                .toUriString();

        // 4. Выполняем редирект
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}