package com.security.jwt.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.jwt.JwtUtil;
import com.security.jwt.model.CustomUserAccount;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


//username, password를 이용해 로그인판단을 하는 필터
//  /login URL일 때 동작
@RequiredArgsConstructor
public class JwtLoginFilter extends UsernamePasswordAuthenticationFilter {

    private  final AuthenticationManager authenticationManager;  //new 로 생성하면 부모의 authenticationManager필드는 null이기 때문에 생성자로 주입.
    private final JwtUtil jwtUtil;


    // 로그인 시도
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            // 요청에서 username, password 추출
            // jwt는 API서버 분리된방식.  username,password는  body에 포함되서 옴.
            // 파라미터에 포함되서 오지않음 보통.  이것때문에 재정의. UsernamePasswordAuthetnctionFilter는 parameter 를 처리함.
            Map<String, String> credentials = new ObjectMapper().readValue(request.getInputStream(), HashMap.class);
            String username = credentials.get("username");
            String password = credentials.get("password");


            //이 부분은 UsernamePasswordAuthetnctionFilter 코드 그대로.
            // AuthenticationManger를 통해 확인하는건
            // 결국 username,password를 가지고 CustomUserDetailsService의 return값(CustomUserAccount)이랑 비교.
            UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken.unauthenticated(username, password);
            this.setDetails(request, authRequest);
            return authenticationManager.authenticate(authRequest);  //여기서 AuthenticationException 발생.
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException("Failed to parse authentication request", e);  //readValue하는과정에서 발생.
        }catch ( AuthenticationException e){
            request.setAttribute("ERROR_CAUSE" , "로그인실패");
            throw  e;  //인증 실패 시  AuthenticationException를 그대로 던져야 security가 로그인실패로 처리잘함.
        }

    }

    // 로그인 성공 → JWT 토큰 발급
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        CustomUserAccount customUserAccount = (CustomUserAccount) authResult.getPrincipal();

        String accessToken = jwtUtil.createAccessToken(customUserAccount.getUsername());
        // 토큰을 응답에 포함
        response.setContentType("application/json");
        response.getWriter().write("{\"access_token\": \"" + accessToken + "\"}");

    }
}

