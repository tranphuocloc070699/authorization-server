package com.server.sso.auth;

import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.server.sso.mail.MailSenderDto;
import com.server.sso.queue.producers.RabbitMQDbProducer;
import com.server.sso.queue.producers.RabbitMQMailProducer;
import jakarta.servlet.RequestDispatcher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;

import com.server.sso.exception.customs.ForbiddenException;
import com.server.sso.exception.customs.UnAuthenticateException;
import com.server.sso.mail.EmailServiceImpl;
import com.server.sso.redis.RedisDataAccess;
import com.server.sso.redis.RedisUser;
import com.server.sso.security.JwtService;
import com.server.sso.security.multiFactor.DefaultMFATokenManager;
import com.server.sso.security.multiFactor.MfaTokenData;
import com.server.sso.shared.AuthResponseException;
import com.server.sso.shared.Constant;
import com.server.sso.shared.ValidateData;
import com.server.sso.user.Provider;
import com.server.sso.user.Role;
import com.server.sso.user.User;
import com.server.sso.user.UserDataAccess;

import dev.samstevens.totp.exceptions.QrGenerationException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

  private final UserDataAccess userDataAccess;
  private final JwtService jwtService;
  private final PasswordEncoder passwordEncoder;
  private final Constant CONST;
  private final RedisDataAccess redisDataAccess;
  private final DefaultMFATokenManager defaultMFATokenManager;
  private final EmailServiceImpl emailService;
  private final RabbitMQDbProducer rabbitMQDbProducer;
  private final RabbitMQMailProducer rabbitMQMailProducer;
  /* === Authenticate Route === */
  public ResponseEntity<AuthResponse> authenticate(HttpServletRequest request,
                                                   HttpServletResponse response) {
    try {
      Optional<String> refreshTokenOptional = jwtService.readServletCookie(request, CONST.JWT_REFRESH_TOKEN_NAME);
      if (refreshTokenOptional.isEmpty()) throw new ForbiddenException("Refresh token not found");
      String refreshToken = refreshTokenOptional.get();
      String userEmail = jwtService.extractUsername(refreshToken);
      if (userEmail == null) throw new UnAuthenticateException("Cannot extract username from this token");

      /*Validate from redis db*/
      Integer refreshTokenVersion = jwtService.extractClaim(refreshToken,claims -> claims.get("refreshTokenVersion",Integer.class));
      RedisUser redisUserExisted = redisDataAccess.findRedisUserByEmail(userEmail);
      if(redisUserExisted==null) throw new UnAuthenticateException("[Redis] User with email [\" + userEmail + \"] not found\"");
      if(refreshTokenVersion==null || !refreshTokenVersion.equals(redisUserExisted.getRefreshTokenVersion())) throw new UnAuthenticateException("[Redis] refresh token not match");

      /*Validate user existing in db*/
      Optional<User> userExisting = userDataAccess.findByEmail(userEmail);
      if (userExisting.isEmpty()) throw new UnAuthenticateException("[Database] User with email [" + userEmail + "] not found");

      /*Validate token expire and user email match from token and db */
      boolean isTokenValid = jwtService.isTokenValid(refreshToken, userExisting.get());
      if(!isTokenValid) throw new UnAuthenticateException("Token invalid");

      /*
      All thing good.
      increase cookie version
      */
      redisUserExisted.setRefreshTokenVersion(redisUserExisted.getRefreshTokenVersion()+1);
      redisDataAccess.save(redisUserExisted);
      jwtService.writeCookie(redisUserExisted.getRefreshTokenVersion(),userExisting.get().getEmail(), response);

      return ResponseEntity.status(HttpStatus.OK).body(AuthResponse.builder()
          .status(HttpStatus.OK)
          .data(userExisting.get())
          .message("authenticated")
          .path(request.getServletPath())
          .accessToken(jwtService.generateToken(userExisting.get().getEmail()))
          .build());
    } catch (ForbiddenException  e) {
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.FORBIDDEN, e.getMessage());
    }
    catch (UnAuthenticateException | JwtException e) {
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.UNAUTHORIZED, e.getMessage());
    }
    catch (RuntimeException e) {
      System.err.println("[authenticate] internal server error :" + e.getMessage());
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
    }
  }
  public String loginView(Authentication authentication, HttpSession session, String redirectUrl) {
    if (authentication != null && authentication.isAuthenticated()) {
      return "redirect:/dashboard";
    }
    if (redirectUrl != null) {
      session.setAttribute("redirectUrl", redirectUrl);
    }
    return "login";
  }

  public String signupView(Authentication authentication, Model model) {
    if (authentication != null && authentication.isAuthenticated()) {
      return "redirect:/dashboard";
    }
    AuthSignUpRequest user = new AuthSignUpRequest();
    model.addAttribute("user", user);
    return "signup";
  }
  public String dashboardView(Authentication authentication, Model model) {
    if (authentication == null || authentication.getName()==null) {
      System.err.println("[AuthService - dashboardView] authentication null");
      return "redirect:/login";
    }
    Optional<User> user = userDataAccess.findByEmail(getName(authentication));
    if ( user.isEmpty() ) {
      System.err.println("[AuthService - dashboardView]  user null");
      return "redirect:/login";
    }
    model.addAttribute("user", user.get());

    return "dashboard";
  }

  public String signup(Authentication authentication, HttpServletRequest request, HttpServletResponse response,
                       HttpSession httpSession, BindingResult result,
                       AuthSignUpRequest user, Model model) {
    try {
      if (result.hasErrors()) {
        return "signup"; // Return back to the form with error messages
      }


      Optional<User> userExisted= userDataAccess.findByEmail(user.getEmail());
      if(userExisted.isPresent()){
        model.addAttribute("errorMessage","Email " + user.getEmail() + " Already exist");
        return "signup";
      }

      if (authentication == null) {


        String key =user.getEmail()+UUID.randomUUID();
        String passwordEncoded = passwordEncoder.encode(user.getPassword());
        RedisUser redisUser = RedisUser.builder()
            .name(user.getName())
            .email(user.getEmail())
            .password(passwordEncoded)
            .provider(Provider.LOCAL)
            .role(Role.USER)
            .refreshTokenVersion(0)
            .isUsing2FA(false)
            .secret(null)
            .createdAt(new Date())
            .updatedAt(new Date())
            .build();
        redisDataAccess.saveTemporary(key,redisUser,300);

        httpSession.setAttribute("email",redisUser.getEmail());
        String token = jwtService.generateToken(key);
        MailSenderDto dto = MailSenderDto.builder()
            .to(user.getEmail())
            .subject("Confirmation")
            .confirmationLink("http://localhost:8080/signup-success?token=" + token)
            .build();
        rabbitMQMailProducer.sendMailRequest(dto);
//        emailService.sendMail(user.getEmail(),"Confirmation","http://localhost:8080/signup-success?token=" + token);
      }
      return "redirect:/signup-instruction";
    } catch (RuntimeException e) {
      System.err.println("saveUser Exception :" + e.getMessage());
      throw new RuntimeException(e.getMessage());
    }
  }

  public String signupInstructionView(Authentication authentication,HttpSession httpSession ,Model model) {
    if (httpSession.getAttribute("email") != null) {
      model.addAttribute("email",httpSession.getAttribute("email"));
      return "signup-instruction";
    }else{
      return "redirect:/login";
    }
  }

  private String getName(Authentication authentication) {
    /*In case login with google but set transform to UsernamePasswordAuthenticationToken
    * at OAuth2LoginSuccessHandler
    * */
    try {
      OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
      String email = oAuth2User.getAttribute("email");
      if(email==null  || email.isEmpty()){
        return "";
      }
      return email;
    } catch (ClassCastException e) {
      return Optional.of(authentication)
          .filter(OAuth2AuthenticationToken.class::isInstance)
          .map(OAuth2AuthenticationToken.class::cast)
          .map(OAuth2AuthenticationToken::getPrincipal)
          .map(OidcUser.class::cast)
          .map(OidcUser::getEmail)
          .orElseGet(authentication::getName);
    }
  }

  public ResponseEntity<AuthResponse> getProfile(HttpServletRequest request, HttpServletResponse response) {
    try{
      final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
      final String jwt;
      final String userEmail;
      if(authHeader==null || !authHeader.startsWith("Bearer ")){
        throw new ForbiddenException("token not found");
      }
      jwt = authHeader.substring(7);
      userEmail = jwtService.extractUsername(jwt);
      if(userEmail==null) throw new UnAuthenticateException("Cannot extract email from token");

      Optional<User> userOptional = userDataAccess.findByEmail(userEmail);
      if(userOptional.isEmpty()) throw new UnAuthenticateException("User not found with this token");

      return ResponseEntity.status(HttpStatus.OK).body(AuthResponse.builder()
          .status(HttpStatus.OK)
          .data(userOptional.get())
          .message("get profile successfully!")
          .path(request.getServletPath())
          .accessToken(jwtService.generateToken(userOptional.get().getEmail()))
          .build());
    }
    catch (ForbiddenException  e) {
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.FORBIDDEN, e.getMessage());
    }
    catch (UnAuthenticateException | JwtException e) {
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.UNAUTHORIZED, e.getMessage());
    }
    catch (RuntimeException e) {
      System.err.println("[authenticate] internal server error :" + e.getMessage());
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
    }
  }

  public  Object toggle2Fa(Authentication authentication, Model model) {
    try {
      if(authentication==null || authentication.getName()==null) throw new ForbiddenException("authentication null");
      String userEmail = getName(authentication);
      if(userEmail==null) throw new UnAuthenticateException("Cannot extract userEmail ["+authentication.getName()+"] from " +
          "authentication");

      Optional<User> userOptional = userDataAccess.findByEmail(userEmail);
      RedisUser redisUser = redisDataAccess.findRedisUserByEmail(userEmail);
      if (userOptional.isEmpty()) throw new UnAuthenticateException("[AuthService - toggle2Fa] User with email [" + userEmail +
          "]" +
          " " +
          "not found");
      if (redisUser==null) throw new UnAuthenticateException("[AuthService - toggle2Fa] Redis user with email [" + userEmail + "]" +
          " not found");
      User userExisting = userOptional.get();
      /*All thing good*/

      if (userExisting.getIsUsing2FA()) {
        /*Disable using2Fa*/
        userExisting.setIsUsing2FA(false);
        userExisting.setSecret(null);
        redisUser.setIsUsing2FA(false);
        redisUser.setSecret(null);
        redisDataAccess.save(redisUser);
        userDataAccess.save(userExisting);
        return ResponseEntity.status(HttpStatus.OK).body(AuthResponse.builder()
            .status(HttpStatus.OK)
            .data(null)
            .message("disable multi factor authenticate successfully!")
            .path(null)
            .accessToken(null)
            .build());
      } else {
        /*Enable using2Fa*/
        userExisting.setIsUsing2FA(true);
        userExisting.setSecret(defaultMFATokenManager.generateSecretKey());
        redisUser.setIsUsing2FA(true);
        redisUser.setSecret(defaultMFATokenManager.generateSecretKey());
        redisDataAccess.save(redisUser);
        userDataAccess.save(userExisting);
        MfaTokenData data = new MfaTokenData(defaultMFATokenManager.getQRCode(userExisting.getSecret(),userExisting.getEmail()),
            userExisting.getSecret());
        return ResponseEntity.status(HttpStatus.OK).body(AuthResponse.builder()
            .status(HttpStatus.OK)
            .data(data)
            .message("enable multi factor authenticate successfully!")
            .path(null)
            .accessToken(null)
            .build());
      }
    }  catch (ForbiddenException  e) {
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.FORBIDDEN, e.getMessage());
    } catch (QrGenerationException e) {
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.BAD_REQUEST, e.getMessage());
    }
    catch (RuntimeException e) {
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
    }
  }

  public Object verifyTest2Fa(Authentication authentication, String value, Model model) {
    if(authentication==null || authentication.getName()==null) throw new ForbiddenException("authentication null");
    String userEmail = getName(authentication);
    if(userEmail==null) throw new UnAuthenticateException("Cannot extract userEmail ["+authentication.getName()+"] from " +
        "authentication");

    Optional<User> userExisting = userDataAccess.findByEmail(userEmail);
    if (userExisting.isEmpty()) throw new UnAuthenticateException("[Database] User with email [" + userEmail + "] not found");

    return defaultMFATokenManager.verifyTotp(value,userExisting.get().getSecret()) ? "Verification successful" : "Verification " +
        "failed";

  }

  public String verifyMultiFactorView(Authentication authentication, Model model,String redirectUrl,HttpServletRequest request) {
    if (authentication == null) {
//      Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
//      String errorMessage = (String) request.getAttribute(RequestDispatcher.ERROR_MESSAGE);
      request.setAttribute(RequestDispatcher.ERROR_STATUS_CODE,HttpStatus.NOT_FOUND);
      request.setAttribute(RequestDispatcher.ERROR_MESSAGE,"Page not found");
      return "redirect:/error";
    }
    return "verify-multi-factor";
  }

  public String verifyMultiFactor(Authentication authentication, Model model, HttpSession httpSession, String numberDigits,
                                  HttpServletRequest request,
                                  HttpServletResponse response) throws IOException {
    if(!ValidateData.isValidLong(numberDigits)){
      model.addAttribute("verifyError","code invalid");
      return "verify-multi-factor";
    }

    String userEmail = getName(authentication);
    if (userEmail == null || userEmail.isEmpty()) {
      model.addAttribute("verifyError","userEmail not found from authentication");
      return "verify-multi-factor";
    }

    Optional<User> userOptional = userDataAccess.findByEmail(userEmail);
    RedisUser redisUser = redisDataAccess.findRedisUserByEmail(userEmail);
    if(userOptional.isEmpty()) {
      model.addAttribute("verifyError","user not found with email: " + userEmail);
      return "verify-multi-factor";
    }
    if(redisUser==null) {
      model.addAttribute("verifyError","redis user not found with email: " + userEmail);
      return "verify-multi-factor";
    }

    User userExisting = userOptional.get();

    if(userExisting.getSecret()==null || userExisting.getSecret().isEmpty()) {
      model.addAttribute("verifyError","Redis user secret is null");
      return "verify-multi-factor";
    }

    if(!defaultMFATokenManager.verifyTotp(numberDigits,userExisting.getSecret())){
      model.addAttribute("verifyError","Verify failure! please enter the code on your Google Authenticator App.");
      return "verify-multi-factor";
    }
    String redirectUrl = (String) httpSession.getAttribute("redirectUrl");
    if (redirectUrl == null) {
        GrantedAuthority userAuthority = new SimpleGrantedAuthority(Role.USER.name());
        List<GrantedAuthority> authorities = Collections.singletonList(userAuthority);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
            userExisting,
            null,
            authorities
        );
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);
        httpSession.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, SecurityContextHolder.getContext());

        redisUser.setRefreshTokenVersion(redisUser.getRefreshTokenVersion()+1);
        redisDataAccess.save(redisUser);
        jwtService.writeCookie(redisUser.getRefreshTokenVersion(),authentication.getName(),response);

      return "redirect:/dashboard";
    }else{
      return redirectUrl;
    }
  }
  public String signupSuccessView(Authentication authentication,HttpSession httpSession,Model model, String token,
                                  HttpServletRequest request,
                                  HttpServletResponse response) {
    if(token==null) return "login";
    String key = jwtService.extractUsername(token);
    if(key==null) return "login";

    RedisUser redisUser = redisDataAccess.findUserTemporaryByKey(key);
    if(redisUser==null) return "login";

    User newUser = User.builder()
          .email(redisUser.getEmail())
          .role(Role.USER)
          .provider(Provider.LOCAL)
          .name(redisUser.getName())
          .password(redisUser.getPassword())
          .isUsing2FA(false)
          .secret(null)
          .build();
    User userSave = userDataAccess.save(newUser);
    rabbitMQDbProducer.sendSaveUserRequestToPostgres(userSave);
    redisUser.setId(userSave.getId());
    if(authentication==null){
              GrantedAuthority userAuthority = new SimpleGrantedAuthority(Role.USER.name());
        List<GrantedAuthority> authorities = Collections.singletonList(userAuthority);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
            newUser,
            null,
            authorities
        );
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);
        httpSession.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, SecurityContextHolder.getContext());
    }
  model.addAttribute("email",newUser.getEmail());
    jwtService.writeCookie(redisUser.getRefreshTokenVersion(),newUser.getEmail(), response);
    redisDataAccess.deleteUserTemporary(key);
    redisDataAccess.save(redisUser);
    return "redirect:/dashboard";
  }
}
