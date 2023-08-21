package com.company.jwt.service.impl;

import com.company.jwt.exception.ApplicationException;
import com.company.jwt.helper.AuthHelper;
import com.company.jwt.helper.SecurityHelper;
import com.company.jwt.model.entity.User;
import com.company.jwt.model.dto.request.AuthenticationRequest;
import com.company.jwt.model.dto.request.RegisterRequest;
import com.company.jwt.model.dto.response.AuthenticationResponse;
import com.company.jwt.model.enums.Exceptions;
import com.company.jwt.repository.UserRepository;
import com.company.jwt.service.IAuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import javax.validation.constraints.NotNull;


@Service
@RequiredArgsConstructor
public class AuthenticationService implements IAuthenticationService {

    private final UserRepository userRepository;
    private final AuthHelper authHelper;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final SecurityHelper securityHelper;

    @Override
    public AuthenticationResponse register(@NotNull RegisterRequest request) {
        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .build();


        User savedUser = userRepository.save(user);

        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        authHelper.saveUserToken(savedUser, accessToken);

        return AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    @Override
    public AuthenticationResponse authenticate(@NotNull AuthenticationRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();

        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        authHelper.revokedAllUserTokens(user);
        authHelper.saveUserToken(user, accessToken);

        return AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    public AuthenticationResponse refreshToken(String authHeader) {

        if (!securityHelper.authHeaderIsValid(authHeader)) {
            throw new ApplicationException(Exceptions.TOKEN_IS_INVALID_EXCEPTION);
        }

        String jwt = authHeader.substring(7);
        String username = jwtService.extractUsername(jwt);

        if (username != null) {
            User user = userRepository.findByEmail(username)
                    .orElseThrow(() -> new UsernameNotFoundException("Username doesn't exist: " + username));

            if (jwtService.isTokenValid(jwt, user)) {
                String accessToken = jwtService.generateToken(user);
                String refreshToken = jwtService.generateRefreshToken(user);

                authHelper.revokedAllUserTokens(user);
                authHelper.saveUserToken(user, accessToken);

                return AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();

            }
        }

        throw new ApplicationException(Exceptions.TOKEN_IS_INVALID_EXCEPTION);
    }

}
