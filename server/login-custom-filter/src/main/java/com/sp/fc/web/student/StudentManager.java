package com.sp.fc.web.student;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Set;

@Component
public class StudentManager implements AuthenticationProvider, InitializingBean {

    private HashMap<String,Student> studentDB = new HashMap<>();


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        /*
        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
        if(studentDB.containsKey(token.getName())){
            Student student = studentDB.get(token.getName());
            return StudentAuthenticationToken.builder()
                    .principal(student)
                    .details(student.getUsername())
                    .authenticated(true)
                    .build();
        }
        //내가 처리할수 없는 토큰은 null로 넘겨야한다.
        return null;
        */
        StudentAuthenticationToken token = (StudentAuthenticationToken) authentication;
        if(studentDB.containsKey(token.getCredentials())){
            Student student = studentDB.get(token.getCredentials());
            return StudentAuthenticationToken.builder()
                    .principal(student)
                    .details(student.getUsername())
                    .authenticated(true)
                    .build();
        }
        //내가 처리할수 없는 토큰은 null로 넘겨야한다.
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        //return authentication == UsernamePasswordAuthenticationToken.class;
        //우리가 검증을 해주는 provider로 동작시켜 주겠다
        return authentication == StudentAuthenticationToken.class;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Set.of(
                new Student("hong","홍길동",Set.of(new SimpleGrantedAuthority("ROLE_STUDENT"))),
                new Student("kang","강아지",Set.of(new SimpleGrantedAuthority("ROLE_STUDENT"))),
                new Student("rang","호랑이",Set.of(new SimpleGrantedAuthority("ROLE_STUDENT")))
        ).forEach(
                //DB에 세팅
                s -> studentDB.put(s.getId(),s)
        );
    }
}
