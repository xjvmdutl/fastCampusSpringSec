package com.sp.fc.web.controller;

import org.springframework.boot.autoconfigure.neo4j.Neo4jProperties;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {
    @RequestMapping("/")
    public String index(){
        return "홈페이지";
    }
    @RequestMapping("/auth")
    public Authentication auth(){
        return SecurityContextHolder.getContext()
                .getAuthentication();
    }

    @RequestMapping("/user")
    @PreAuthorize("hasAnyAuthority('ROLE_USER')")
    public SecurityMessage user(){//user접근
        return SecurityMessage.builder()
                .auth(SecurityContextHolder.getContext().getAuthentication())
                .message("User 정보")
                .build();
    }

    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    @RequestMapping("/admin")
    public SecurityMessage admin(){//관리자 접근
        return SecurityMessage.builder()
                .auth(SecurityContextHolder.getContext().getAuthentication())
                .message("관리자 정보")
                .build();
    }
}
