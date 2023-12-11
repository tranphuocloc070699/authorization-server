package com.server.sso.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthLogInRequest {
  @NotEmpty(message = "The email is required.")
  @Email(message = "The email address is invalid.", flags = { Pattern.Flag.CASE_INSENSITIVE })
  private String email;

  @NotEmpty(message = "The password is required.")
  private String password;
}
