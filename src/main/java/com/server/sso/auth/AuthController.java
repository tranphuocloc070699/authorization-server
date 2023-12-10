package com.server.sso.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("auth")
public class AuthController {

  @PostMapping("register")
  public Object register(){

  }

  @PostMapping("login")
  public Object login(){

  }

  @GetMapping("authenticate")
  public Object authenticate(HttpServletRequest request,HttpServletResponse response){

  }
}
