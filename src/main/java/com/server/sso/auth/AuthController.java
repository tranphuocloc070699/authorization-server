package com.server.sso.auth;

import java.io.IOException;

import org.springframework.data.repository.query.Param;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;

  /*
  * Scope: Public
  * Uses: Render login page
  * Notes: Navigate to dashboard when authenticated
  * */
  @GetMapping("/login")
  public String loginView(@Param("redirectUrl") String redirectUrl,
                          HttpSession session,
      Model model,
      Authentication authentication) {
    return authService.loginView(authentication, session, redirectUrl);
  }

  /*
   * Scope: Public
   * Uses: Render signup page
   * Notes: Navigate to dashboard when authenticated
   * */
  @GetMapping("/signup")
  public String signupView(Model model, Authentication authentication,@Param("redirectUrl") String redirectUrl,HttpSession session) {

    return authService.signupView(authentication, model,redirectUrl,session);
  }

  /*
   * Scope: Private
   * Uses: Render dashboard page
   * Notes: Navigate to login when un-authenticated
   * */
  @GetMapping("/dashboard")
  public String dashboardView(Authentication authentication, Model model) {
    return authService.dashboardView(authentication, model);
  }

  /*
   * Scope: Public
   * Uses: Render verify-multi-factor page
   * Notes: Navigate to /login when un-authenticated -> navigate to /dashboard when authenticated
   * */
  @GetMapping("/verify-multi-factor")
  public String verifyMultiFactorView(Authentication authentication, Model model,
      @Param("redirectUrl") String redirectUrl,HttpServletRequest request) {
    return authService.verifyMultiFactorView(authentication, model, redirectUrl,request);
  }

  /*
   * Scope: Public
   * Uses: Render signup-instruction
   * Notes: Navigate to /login when un-authenticated -> navigate to /dashboard when authenticated
   * */
  @GetMapping("/signup-instruction")
  public String signupInstructionView(Authentication authentication, HttpSession httpSession, Model model) {
    return authService.signupInstructionView(authentication, httpSession, model);
  }

  /*
   * Scope: Public
   * Uses: Verify token from email
   * */
  @GetMapping("/signup-success")
  public String signupSuccessView(Model model, @RequestParam("token") String token,@RequestParam("redirectUrl") String redirectUrl, HttpSession httpSession,
      HttpServletRequest request,
      HttpServletResponse response, Authentication authentication) {
    return authService.signupSuccess(authentication, httpSession, model, token, request, response,redirectUrl);
  }

  /*
   * Scope: Public
   * Uses: Verify otp from Google Authenticator App
   * Notes: Navigate to /login when un-authenticated
   *        Not render template
   * */
  @PostMapping("/verify-multi-factor")
  public String verifyMultiFactor(Authentication authentication,
      Model model,
      HttpSession httpSession,
      @RequestParam("first") String first,
      @RequestParam("second") String second,
      @RequestParam("third") String third,
      @RequestParam("fourth") String fourth,
      @RequestParam("fifth") String fifth,
      @RequestParam("sixth") String sixth,
      HttpServletRequest request,
      HttpServletResponse response) {

    try {
      String numberDigits;
      if(first.isEmpty() || second.isEmpty() || third.isEmpty() || fourth.isEmpty() || fifth.isEmpty() || sixth.isEmpty()){
        model.addAttribute("verifyError","code must be 6 character, please enter the code on your Google Authenticator App");
        return "verify-multi-factor";
      }
      numberDigits = first+second+third+fourth+fifth+sixth;
      return authService.verifyMultiFactor(authentication, model, httpSession, numberDigits,request, response);
    } catch (IOException e) {
      System.err.println("[AuthController - POST] verifyMultiFactor error: " + e.getMessage());
      return "login";
    }
  }

  /*
   * Scope: Public
   * Uses: Verify user info to signup
   * Notes: Navigate to /signup when un-authenticated
   *        Not render template
   * */
  @PostMapping("/users/save")
  public String verifyUserToSignup(@Valid @ModelAttribute("user") AuthSignUpRequest user, BindingResult result,
      Authentication authentication, HttpSession httpSession, HttpServletRequest request,
      HttpServletResponse response, Model model) {
    return authService.signup(authentication, request, response, httpSession, result, user, model);
  }

}
