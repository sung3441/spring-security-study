package com.example.study.controller;

import com.example.study.dto.LoginDto;
import com.example.study.dto.TokenDto;
import com.example.study.dto.UserDto;
import com.example.study.jwt.JwtFilter;
import com.example.study.jwt.TokenProvider;
import com.example.study.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@Slf4j
@RestController
@RequestMapping("/api")
public class AuthController {

    private final TokenProvider tokenProvider;
    private final UserService userService;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    public AuthController(TokenProvider tokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder, UserService userService) {
        this.tokenProvider = tokenProvider;
        this.userService = userService;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody LoginDto loginDto) {

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String accessToken = tokenProvider.createAccessToken(authentication);
        String refreshToken = tokenProvider.createRefreshToken(authentication);

        // refreshToken 저장
        userService.saveRefreshToken(loginDto.getUsername(), refreshToken);

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + accessToken);

        return new ResponseEntity<>(new TokenDto(accessToken, refreshToken), httpHeaders, HttpStatus.OK);
    }

    @GetMapping("/refresh")
    public ResponseEntity<TokenDto> refreshToken(@RequestParam(name = "refreshToken") String refreshToken) {

        log.info("refershToken  = {}", refreshToken);

        if (!tokenProvider.validateToken(refreshToken)) {
            throw new RuntimeException("토근이 유효하지 않습니다.");
        }

        Authentication authentication = tokenProvider.getAuthentication(refreshToken);
        String accessToken = tokenProvider.createRefreshToken(authentication);
        String newRefreshToken = tokenProvider.createRefreshToken(authentication);

        userService.saveRefreshToken(authentication.getName(), newRefreshToken);

        return new ResponseEntity<>(new TokenDto(accessToken, newRefreshToken), HttpStatus.OK);
    }
}
