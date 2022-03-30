package io.security.corespringsecurity.domain;

import lombok.Builder;
import lombok.Data;
import org.springframework.security.crypto.password.PasswordEncoder;

@Data
@Builder
public class AccountDto {

    private String username;
    private String password;
    private String email;
    private String age;
    private String role;

    public Account toAccount() {
        return Account.builder()
                .username(username)
                .password(password)
                .email(email)
                .age(age)
                .role(role)
                .build();
    }

    public AccountDto encodePassword(PasswordEncoder passwordEncoder) {
        password = passwordEncoder.encode(password);
        return this;
    }
}
