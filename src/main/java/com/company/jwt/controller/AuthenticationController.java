package com.company.jwt.controller;

import com.company.jwt.model.dto.request.AuthenticationRequest;
import com.company.jwt.model.dto.request.RegisterRequest;
import com.company.jwt.model.dto.response.AuthenticationResponse;
import com.company.jwt.service.impl.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.*;


@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public AuthenticationResponse register(@RequestBody RegisterRequest request) {
        return authenticationService.register(request);
    }

    @PostMapping("/authenticate")
    public AuthenticationResponse authenticate(@RequestBody AuthenticationRequest request) {
        return authenticationService.authenticate(request);
    }

    @PostMapping("/refresh-token")
    public AuthenticationResponse refreshToken(@RequestHeader(name = HttpHeaders.AUTHORIZATION) String token) {
        return authenticationService.refreshToken(token);
    }

}
