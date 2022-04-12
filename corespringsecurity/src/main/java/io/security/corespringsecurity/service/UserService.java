package io.security.corespringsecurity.service;

import io.security.corespringsecurity.controller.domain.entity.Account;

public interface UserService {

    void createUser(Account account);
}
