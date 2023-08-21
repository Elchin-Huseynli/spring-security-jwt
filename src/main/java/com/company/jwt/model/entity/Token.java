package com.company.jwt.model.entity;

import com.company.jwt.model.enums.TokenType;
import lombok.*;
import lombok.experimental.FieldDefaults;
import javax.persistence.*;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class Token {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long id;

    String token;

    @Enumerated(EnumType.STRING)
    @Builder.Default
    TokenType tokenType = TokenType.BEARER;

    boolean expired;

    boolean revoked;

    @ManyToOne
    @JoinColumn(name = "user_id")
    User user;
}
