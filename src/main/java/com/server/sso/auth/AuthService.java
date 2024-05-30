package com.server.sso.auth;

import com.server.sso.mail.MailSenderDto;
import com.server.sso.queue.producers.RabbitMQDbProducer;
import com.server.sso.queue.producers.RabbitMQMailProducer;
import com.server.sso.redis.RedisDataAccess;
import com.server.sso.redis.RedisUser;
import com.server.sso.security.JwtService;
import com.server.sso.security.multiFactor.DefaultMFATokenManager;
import com.server.sso.shared.Constant;
import com.server.sso.shared.ExtractData;
import com.server.sso.shared.ValidateData;
import com.server.sso.user.Provider;
import com.server.sso.user.Role;
import com.server.sso.user.User;
import com.server.sso.user.UserDataAccess;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;

import java.io.IOException;
import java.util.*;

@Service
@RequiredArgsConstructor
public class AuthService {

  private final UserDataAccess userDataAccess;
  private final JwtService jwtService;
  private final PasswordEncoder passwordEncoder;
  private final Constant CONST;
  private final RedisDataAccess redisDataAccess;
  private final DefaultMFATokenManager defaultMFATokenManager;
  private final RabbitMQDbProducer rabbitMQDbProducer;
  private final RabbitMQMailProducer rabbitMQMailProducer;

  /*
  * Uses: render login page
  * Case: Authenticate!=null (already authenticate):
  *       - Case: redirectUrl params:
  *         - True: navigate to redirectUrl
  *         - False: navigate to dashboard
  * */
  public String loginView(Authentication authentication, HttpSession session, String redirectUrl) {
    if (authentication != null && authentication.isAuthenticated()) {
      return "redirect:/dashboard";
    }
    if (redirectUrl != null) {
      session.setAttribute("redirectUrl", redirectUrl);
    }
    return "login";
  }

  /*
   * Uses: render login page
   * Case: Authenticate!=null (already authenticate):
   *        - navigate to dashboard
   * */
  public String signupView(Authentication authentication, Model model,String redirectUrl,HttpSession session) {
    if (authentication != null && authentication.isAuthenticated()) {
      return "redirect:/dashboard";
    }
    
    AuthSignUpRequest user = new AuthSignUpRequest();
    if (redirectUrl != null) {
      user.setRedirectUrl(redirectUrl);
      session.setAttribute("redirectUrl", redirectUrl);
    }
    model.addAttribute("user", user);
    return "signup";
  }

  /*
   * Uses: render dashboard page
   * Case: Authenticate==null:
   *        - Navigate to log in
   * Case: user from database == null:
   *        - Navigate to log in
   * */
  public String dashboardView(Authentication authentication, Model model) {
    if (authentication == null || authentication.getName()==null) {
      System.err.println("[AuthService - dashboardView] authentication null");
      return "redirect:/login";
    }
    Optional<User> user = userDataAccess.findByEmail(ExtractData.getName(authentication));
    if ( user.isEmpty() ) {
      System.err.println("[AuthService - dashboardView]  user null");
      return "redirect:/login";
    }
    model.addAttribute("user", user.get());
    return "dashboard";
  }

  /*
   * Uses: verify to user to sign up new user
   * Case: Form validation fail:
   *        - Navigate back to signup page
   * Case: User already exist in database:
   *        - Navigate back to signup page
   * Case: Authenticate == null (check to avoid unknown conflict):
   *        - Generate temporary key
   *        - Encode Password
   *        - Save temporary to redis | TTL : 300s
   *        - Save user mail to Http Session
   *        - Generate token contains user redis key
   *        - Send token to RabbitMQ Broker -> Consumer will send mail to specific email
   *        - Redirect to signup-instruction page (for instruct user finish sign up process)
   * */
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
        String confirmationLink = CONST.APP_DOMAIN+ "/signup-success?token=" + token;
        if (user.getRedirectUrl()!=null) {
          confirmationLink = confirmationLink+"&redirectUrl="+user.getRedirectUrl();
        }
        MailSenderDto dto = MailSenderDto.builder()
            .to(user.getEmail())
            .subject("Confirmation")
            .confirmationLink(confirmationLink)
            .build();
        rabbitMQMailProducer.sendMailRequest(dto);
      }
      return "redirect:/signup-instruction";
    } catch (RuntimeException e) {
      System.err.println("saveUser Exception :" + e.getMessage());
      throw new RuntimeException(e.getMessage());
    }
  }

  /*
   * Uses: render signup-instruction page
   * Case: Extract user from httpSession:
   *         - True: render signup-instruction page
   *         - False: redirect to login page
   * */
  public String signupInstructionView(Authentication authentication,HttpSession httpSession ,Model model) {
    if (httpSession.getAttribute("email") != null) {
      model.addAttribute("email",httpSession.getAttribute("email"));
      return "signup-instruction";
    }else{
      return "redirect:/login";
    }
  }

  /*
   * Uses: render verify-multi-factor page
   * Case: Authentication == null:
   *         - True: redirect to login page
   *         - False: render verify-multi-factor page
   * */
  public String verifyMultiFactorView(Authentication authentication, Model model,String redirectUrl,HttpServletRequest request) {
    if (authentication == null) {
      return "redirect:/login";
    }
    return "verify-multi-factor";
  }

  /*
   * Uses: Verify OTP of Google Authenticator App from user
   * Case: Authentication == null:
   *      - Redirect login page
   * Case: OTP not a number:
   *      - Return verify-multi-factor page with specific error
   * Case: Cannot extract user email from authentication:
   *      - Return verify-multi-factor page with specific error
   * Case: Non-exist user or redis user:
   *      - Return verify-multi-factor page with specific error
   * Case: Non-value user secret:
   *      - Return verify-multi-factor page with specific error
   * Case: VerifyTopt fail:
   *      - Return verify-multi-factor page with specific error
   * Case: All thing good!!!
   *      - Increase refreshToken version
   *      - Save redis user
   *      - Write cookie to request
   *      - Case: Exist redirectUrl:
   *            - True: Navigate to redirectUrl
   *            - False: Set authentication
   * */
  public String verifyMultiFactor(Authentication authentication, Model model, HttpSession httpSession, String numberDigits,
                                  HttpServletRequest request,
                                  HttpServletResponse response) throws IOException {

    if (authentication == null) {
      return "redirect:/login";
    }

    if(!ValidateData.isValidLong(numberDigits)){
      model.addAttribute("verifyError","Code invalid");
      return "verify-multi-factor";
    }
    String userEmail = ExtractData.getName(authentication);
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
    redisUser.setRefreshTokenVersion(redisUser.getRefreshTokenVersion()+1);
    redisDataAccess.save(redisUser);
    jwtService.writeCookie(redisUser.getRefreshTokenVersion(),authentication.getName(),response);
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
      return "redirect:/dashboard";
    }else{
      return redirectUrl;
    }
  }

  /*
   * Uses: Verify OTP of Google Authenticator App from user
   * Case: token (from email) == null:
   *      - Redirect signup page
   * Case: Cannot extract key from token:
   *      - Return signup page
   * Case: Non-exist redis user:
   *      - Return signup page
   * Case: All thing good!!!
   *      - Create new user
   *      - Save new user
   *      - Send user to RabbitMQ Broker -> consumer will save this user to database
   *      - modify redis user data from temporary redis user (create temporary data redis user when signup)
   *      - delete redis user temporary
   *      - Case: Authenticate == null (avoid unknown conflict)
   *            - True: Set Authenticate
   *      - Write cookie to request
   *      - Redirect to dashboard
   * */
  public String signupSuccess(Authentication authentication,HttpSession httpSession,Model model, String token,
                                  HttpServletRequest request,
                                  HttpServletResponse response,String redirectUrl) {
    if (token == null) {
      model.addAttribute("errorMessage","Sign up failure! Cannot get token from url");
      return "signup";
    }
    String key = jwtService.extractUsername(token);
    if (key == null) {
      model.addAttribute("errorMessage","Sign up failure! Cannot extract key from token");
      return "signup";
    }

    RedisUser redisUser = redisDataAccess.findUserTemporaryByKey(key);
    if (redisUser == null) {
      model.addAttribute("errorMessage","Sign up failure! Cannot get redis user from the key");
      return "signup";
    }

    /*Save new user*/
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

    /*RabbitMQ*/
    rabbitMQDbProducer.sendSaveUserRequestToPostgres(userSave);

    /*Modify redis*/
    redisUser.setId(userSave.getId().toString());
    redisDataAccess.deleteUserTemporary(key);
    redisDataAccess.save(redisUser);

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
//    model.addAttribute("email",newUser.getEmail());
    jwtService.writeCookie(redisUser.getRefreshTokenVersion(),newUser.getEmail(), response);
    
    
    try {
      System.out.println("before Redirect");
      response.sendRedirect(redirectUrl != null ? redirectUrl : "/dashboard");
    } catch (IOException e) {
      System.err.println("[signupSuccess] sendRedirect error" + e.getMessage());
      throw new RuntimeException(e);
    }
  return null;

//    return "redirect:/dashboard";
  }
}
