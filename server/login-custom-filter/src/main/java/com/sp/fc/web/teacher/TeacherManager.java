package com.sp.fc.web.teacher;

import com.sp.fc.web.student.Student;
import com.sp.fc.web.student.StudentAuthenticationToken;
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
public class TeacherManager implements AuthenticationProvider, InitializingBean {

    private HashMap<String, Teacher> teacherDB = new HashMap<>();


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        TeacherAuthenticationToken token = (TeacherAuthenticationToken) authentication;
        if(teacherDB.containsKey(token.getCredentials())){
            Teacher teacher = teacherDB.get(token.getCredentials());
            return TeacherAuthenticationToken.builder()
                    .principal(teacher)
                    .details(teacher.getUsername())
                    .authenticated(true)
                    .build();
        }
        //내가 처리할수 없는 토큰은 null로 넘겨야한다.
        return null;

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication == TeacherAuthenticationToken.class;
        //우리가 검증을 해주는 provider로 동작시켜 주겠다
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Set.of(
                new Teacher("choi","최선생",Set.of(new SimpleGrantedAuthority("ROLE_TEACHER")))
        ).forEach(
                //DB에 세팅
                s -> teacherDB.put(s.getId(),s)
        );
    }
}