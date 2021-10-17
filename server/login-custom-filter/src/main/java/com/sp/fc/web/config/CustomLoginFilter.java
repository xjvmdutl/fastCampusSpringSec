package com.sp.fc.web.config;

import com.sp.fc.web.student.StudentAuthenticationToken;
import com.sp.fc.web.teacher.TeacherAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CustomLoginFilter extends UsernamePasswordAuthenticationFilter {

    public CustomLoginFilter(AuthenticationManager authenticationManager){
        super(authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = obtainUsername(request);
        username = (username != null) ? username : "";
        username = username.trim();
        String password = obtainPassword(request);
        password = (password != null) ? password : "";

        String type = request.getParameter("type");
        //type값 가지고 오기
        if(type == null || !type.equals("teacher")){
            //student
            StudentAuthenticationToken tokens = StudentAuthenticationToken.builder()
                                                .credentials(username)
                                                .build();
            return this.getAuthenticationManager().authenticate(tokens);
        }else{
            //teacher
            TeacherAuthenticationToken tokens = TeacherAuthenticationToken.builder()
                                                .credentials(username)
                                                .build();
            return this.getAuthenticationManager().authenticate(tokens);
        }
    }
}
