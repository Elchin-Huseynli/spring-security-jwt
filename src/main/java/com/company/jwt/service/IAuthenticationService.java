package com.company.jwt.service;

import com.company.jwt.model.dto.request.AuthenticationRequest;
import com.company.jwt.model.dto.request.RegisterRequest;
import com.company.jwt.model.dto.response.AuthenticationResponse;


public interface IAuthenticationService {
    AuthenticationResponse register(RegisterRequest request);
    AuthenticationResponse authenticate(AuthenticationRequest request);
    AuthenticationResponse refreshToken(String authHeader);

}



