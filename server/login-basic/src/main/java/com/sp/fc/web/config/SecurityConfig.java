package com.sp.fc.web.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;

@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomAuthDetails customAuthDetails;

    public SecurityConfig(CustomAuthDetails customAuthDetails){
        this.customAuthDetails = customAuthDetails;
    }
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //동작하지 않는다
        //why? CSRF Filter에서 actualToken이 null이기 때문
        //-> th:action으로 동작하게하여 actualToken값을 채워준다.
        auth
                .inMemoryAuthentication()
                .withUser(
                        User.withDefaultPasswordEncoder()
                        .username("user1")
                        .password("1111")
                        .roles("USER")
                ).withUser(
                User.withDefaultPasswordEncoder()//테스트시 한정해서 encoding을 쓸수 있도록 메소드가 있다
                .username("admin")
                .password("2222")
                .roles("ADMIN")
        );
    }
    @Bean
    RoleHierarchy roleHierarchy(){
        //관리자는 user정보도 볼수 있어야 되기 때문에 해당 bean을 등록한다.
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
        return roleHierarchy;
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(request->{
                    request
                            .antMatchers("/").permitAll()// root(/)페이지는 모든 사람들이 접근 가능하도록 하고
                            .anyRequest().authenticated()//다른 모든 경로는 허락을 받고 들어오도록함(단, 리소스 또한 허락을 받아야 되므로 css가 동작 x(

                            ;
                })
                .formLogin(
                        login -> login.loginPage("/login")
                        .permitAll()//로그인 페이지에서 해당 permitAll을 쓰지 않게되면 무한 loop가 돌수 있다.
                        //로그인을 하였지만 다시 받으라고 하는 루프에 빠지게되는것을 방지하기 위해 .permitAll()을 설정 한다.
                        .defaultSuccessUrl("/",false)
                        //alwaysUse를 false로 하여 main페이지가 아닌 그페이지의 성공화면에 머물게 한다
                        .failureUrl("/login-error")//로그인 실페시 경로 등록
                        .authenticationDetailsSource(customAuthDetails)
                )//form 로그인 설정, //설정을 하지 않게 된다면 디폴트로 된 페이지를 띄우게 된다.
                .logout(
                        logout-> logout.logoutSuccessUrl("/")
                        //현재 페이지에서 로그아웃을 하게 되면 /url로 가게된다
                )
                .exceptionHandling(exception->exception.accessDeniedPage("/access-denied"))
                //에러 화면 이동
                ;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        //webResource에 대해서는 security가 동작 안하도록 ignore시켜야함
        web.ignoring()
                .requestMatchers(
                        //js/*
                        //css/*
                        //images/*
                        //경로들은 모두 해당 locations로 잡힌다.
                        PathRequest.toStaticResources().atCommonLocations()
                );
    }
}
