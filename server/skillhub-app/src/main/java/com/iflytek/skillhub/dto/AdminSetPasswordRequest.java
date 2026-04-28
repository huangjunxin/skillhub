package com.iflytek.skillhub.dto;

import jakarta.validation.constraints.NotBlank;

public record AdminSetPasswordRequest(
    @NotBlank(message = "validation.auth.local.password.notBlank")
    String newPassword
) {}