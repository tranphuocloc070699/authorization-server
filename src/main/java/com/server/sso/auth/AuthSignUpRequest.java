package com.server.sso.auth;

import com.server.sso.user.Role;
import lombok.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;

import jakarta.validation.constraints.Pattern;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthSignUpRequest {

  @NotEmpty(message = "The email is required.")
  @Email(message = "The email address is invalid.", flags = { Pattern.Flag.CASE_INSENSITIVE })
  private String email;

  @NotEmpty(message = "The password is required.")
  private String password;

  @NotEmpty(message = "The name is required.")
  private String name;

  private Role role;
  
  private String redirectUrl;
}