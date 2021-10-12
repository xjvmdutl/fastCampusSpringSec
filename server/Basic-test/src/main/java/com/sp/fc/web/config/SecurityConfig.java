package com.sp.fc.web.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true)//지금부터 prePost로 권한체크
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    //사용자 추가를 여기서 가능하다.
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        //해당 설정을 하게 되면 application.yml에서 설정한 것은 무시하게 된다.
        auth.inMemoryAuthentication()
                .withUser(User.builder()
                        .username("user2")
                        .password(passwordEncoder().encode("2222"))
                        .roles("USER")
                ).withUser(User.builder()
                            .username("admin")
                            .password(passwordEncoder().encode("3333"))
                            .roles("ADMIN"))
                ;
    }
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    //누구나 접속할수 있게 하는 방법
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /*
        super.configure(http);
        =======================
        http.authorizeRequests((requests)
            -> requests.anyRequest().authenticated());//어떤 상태에서든 모두 인증 받은 상태로 하라고 부모에 설정되있다.
        http.formLogin();
        http.httpBasic();
        * */
        http.authorizeRequests((requests) ->
                requests.antMatchers("/").permitAll()
                    .anyRequest().authenticated());
        http.formLogin();
        http.httpBasic();
    }
}
