package com.iflytek.skillhub.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record AdminCreateUserRequest(
    @NotBlank @Pattern(regexp = "^[A-Za-z0-9_]{3,64}$", message = "validation.auth.local.username.invalid")
    String username,
    @NotBlank @Email(message = "validation.auth.local.email.invalid")
    String email,
    @NotBlank(message = "validation.auth.local.password.notBlank")
    String password,
    @NotBlank(message = "validation.auth.local.displayName.notBlank")
    String displayName
) {}