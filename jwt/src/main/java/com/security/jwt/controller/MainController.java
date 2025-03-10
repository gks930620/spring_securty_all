package com.security.jwt.controller;


import com.security.jwt.model.CustomUserAccount;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.security.Principal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("/api")
public class MainController {

    //로그인 후
    @RequestMapping("/my/info")
    @ResponseBody
    public String  myInfo(@AuthenticationPrincipal CustomUserAccount customUserAccount
        ){
        StringBuilder sb=new StringBuilder();
        sb.append(  "권한 : "+    customUserAccount.getAuthorities().iterator().next().getAuthority() +"<br>"   );  //첫번째권한.
        sb.append(  "password : "+  customUserAccount.getPassword()  +"<br> ");
        sb.append(  "username : "+  customUserAccount.getUsername() + "<br>" );
        return sb.toString();
        //api서버에서는 보통 DTO로 보내지만..
    }



}
