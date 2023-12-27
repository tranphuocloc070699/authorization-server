package com.server.sso.auth;

import com.server.sso.errors.customs.ForbiddenException;
import com.server.sso.errors.customs.UnAuthenticateException;
import com.server.sso.redis.RedisDataAccess;
import com.server.sso.redis.RedisUser;
import com.server.sso.security.JwtService;
import com.server.sso.security.multiFactor.DefaultMFATokenManager;
import com.server.sso.security.multiFactor.MFATokenData;
import com.server.sso.shared.AuthResponseException;
import com.server.sso.shared.Constant;
import com.server.sso.shared.ExtractData;
import com.server.sso.shared.ValidateData;
import com.server.sso.user.Role;
import com.server.sso.user.User;
import com.server.sso.user.UserDataAccess;
import dev.samstevens.totp.exceptions.QrGenerationException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthRestService {
  private final UserDataAccess userDataAccess;
  private final JwtService jwtService;
  private final Constant CONST;
  private final RedisDataAccess redisDataAccess;
  private final DefaultMFATokenManager defaultMFATokenManager;

  /*
  * Uses: get access token from refresh token
  * Case: Cannot read token from cookie:
  *      - Throw Error
  * Case: Cannot extract user from token:
  *      - Throw Error
  * Case: Non-exist redis user:
  *      - Throw Error
  * Case: refresh token version not equals from database (when signup or login success, increase refresh token version):
  *      - Throw Error
  * Case: Non-exist user:
  *      - Throw Error
  * Case: Token invalid (user email not equals vs database or token expired):
  *      - Throw Error
  * Case: All thing good!!!
  *      - Increase refresh token version
  *      - Save redis user
  *      - Write cookie to request
  *      - Return response data
  * */
  public ResponseEntity<AuthResponse> authenticate(HttpServletRequest request,
                                                   HttpServletResponse response) {
    try {
      Optional<String> refreshTokenOptional = jwtService.readServletCookie(request, CONST.JWT_REFRESH_TOKEN_NAME);
      if (refreshTokenOptional.isEmpty()) throw new ForbiddenException("Refresh token not found");
      String refreshToken = refreshTokenOptional.get();
      String userEmail = jwtService.extractUsername(refreshToken);
      if (userEmail == null) throw new UnAuthenticateException("Cannot extract username from this token");

      /*Validate from redis db*/
      Integer refreshTokenVersion = jwtService.extractClaim(refreshToken,
          claims -> claims.get("refreshTokenVersion", Integer.class));
      RedisUser redisUserExisted = redisDataAccess.findRedisUserByEmail(userEmail);
      if (redisUserExisted == null) throw new UnAuthenticateException("[Redis] User with email [\" + userEmail + \"] not found\"");
      if (refreshTokenVersion == null || !refreshTokenVersion.equals(redisUserExisted.getRefreshTokenVersion()))
        throw new UnAuthenticateException("[Redis] refresh token not match");

      /*Validate user existing in db*/
      Optional<User> userExisting = userDataAccess.findByEmail(userEmail);
      if (userExisting.isEmpty()) throw new UnAuthenticateException("[Database] User with email [" + userEmail + "] not found");

      /*Validate token expire and user email match from token and db */
      boolean isTokenValid = jwtService.isTokenValid(refreshToken, userExisting.get());
      if (!isTokenValid) throw new UnAuthenticateException("Token invalid");

      /*
      All thing good.
      increase cookie version
      */
      redisUserExisted.setRefreshTokenVersion(redisUserExisted.getRefreshTokenVersion() + 1);
      redisDataAccess.save(redisUserExisted);
      jwtService.writeCookie(redisUserExisted.getRefreshTokenVersion(), userExisting.get().getEmail(), response);

      return ResponseEntity.status(HttpStatus.OK).body(AuthResponse.builder()
          .status(HttpStatus.OK)
          .data(userExisting.get())
          .message("authenticated")
          .path(request.getServletPath())
          .accessToken(jwtService.generateToken(userExisting.get().getEmail()))
          .build());
    } catch (ForbiddenException e) {
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.FORBIDDEN, e.getMessage());
    } catch (UnAuthenticateException | JwtException e) {
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.UNAUTHORIZED, e.getMessage());
    } catch (RuntimeException e) {
      System.err.println("[authenticate] internal server error :" + e.getMessage());
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
    }
  }

  /*
   * Uses: Enable or disable 2FA feature
   * Case: Authenticate==null:
   *     - Throw Error
   * Case: Cannot extract user email from authentication:
   *     - Throw Error
   * Case: Non-exist redis user:
   *     - Throw Error
   * Case: All thing good!!!
   *      - Case: Enable 2FA:
   *         - Generate QR code and mfa code
   *         - return response data
   *      - Case: Disable 2FA:
   *         - update user and user redis
   *         - return response data
   * */
  public Object toggle2Fa(Authentication authentication, Model model) {
    try {
      if (authentication == null || authentication.getName() == null) throw new ForbiddenException("authentication null");
      String userEmail = ExtractData.getName(authentication);
      if (userEmail == null) throw new UnAuthenticateException("Cannot extract userEmail [" + authentication.getName() + "] from " +
          "authentication");

      Optional<User> userOptional = userDataAccess.findByEmail(userEmail);
      RedisUser redisUser = redisDataAccess.findRedisUserByEmail(userEmail);
      if (userOptional.isEmpty()) throw new UnAuthenticateException("[AuthService - toggle2Fa] User with email [" + userEmail +
          "]" +
          " " +
          "not found");
      if (redisUser == null)
        throw new UnAuthenticateException("[AuthService - toggle2Fa] Redis user with email [" + userEmail + "]" +
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
        String secret = defaultMFATokenManager.generateSecretKey();
        /*Get qr code */
//        userExisting.setIsUsing2FA(true);
        userExisting.setSecret(secret);
//        redisUser.setIsUsing2FA(true);
        redisUser.setSecret(secret);
        redisDataAccess.save(redisUser);
        userDataAccess.save(userExisting);

        MFATokenData data = new MFATokenData(defaultMFATokenManager.getQRCode(secret, userExisting.getEmail()),
            secret);
        return ResponseEntity.status(HttpStatus.OK).body(AuthResponse.builder()
            .status(HttpStatus.OK)
            .data(data)
            .message("Get Qr code successfully!")
            .path(null)
            .accessToken(null)
            .build());
      }
    } catch (ForbiddenException e) {
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.FORBIDDEN, e.getMessage());
    } catch (QrGenerationException e) {
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.BAD_REQUEST, e.getMessage());
    } catch (RuntimeException e) {
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
    }
  }

  /*
   * Uses: Verify OTP of Google Authenticator App from user
   * Case: Authentication == null:
   *      - Return specific error
   * Case: OTP not a number:
   *      - Return specific error
   * Case: Cannot extract user email from authentication:
   *      - Return specific error
   * Case: Non-exist user or redis user:
   *      - Return specific error
   * Case: Non-value user secret:
   *      - Return specific error
   * Case: VerifyTopt fail:
   *      - Return specific error
   * Case: All thing good!!!
   *      - Update user and redis user
   *      - Return response data
   * */
  public ResponseEntity<AuthResponse> verifyMultiFactorInDashboardPageToEnable2FA(Authentication authentication,  String numberDigits,
                                  HttpServletRequest request
                                  )  {

    if (authentication == null) {
      return ResponseEntity.status(HttpStatus.FORBIDDEN).body(AuthResponse.builder()
          .status(HttpStatus.FORBIDDEN)
          .data(null)
          .message("Authentication null")
          .path(request.getServletPath())
          .accessToken(null)
          .build());
    }


    if(!ValidateData.isValidLong(numberDigits)){
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(AuthResponse.builder()
          .status(HttpStatus.BAD_REQUEST)
          .data(null)
          .message("Code Invalid")
          .path(request.getServletPath())
          .accessToken(null)
          .build());
    }
    String userEmail = ExtractData.getName(authentication);
    if (userEmail == null || userEmail.isEmpty()) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(AuthResponse.builder()
          .status(HttpStatus.UNAUTHORIZED)
          .data(null)
          .message("Cannot extract user email from authentication")
          .path(request.getServletPath())
          .accessToken(null)
          .build());
    }

    Optional<User> userOptional = userDataAccess.findByEmail(userEmail);
    RedisUser redisUser = redisDataAccess.findRedisUserByEmail(userEmail);
    if(userOptional.isEmpty()) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(AuthResponse.builder()
          .status(HttpStatus.UNAUTHORIZED)
          .data(null)
          .message("User not found with email:" + userEmail)
          .path(request.getServletPath())
          .accessToken(null)
          .build());
    }
    if(redisUser==null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(AuthResponse.builder()
          .status(HttpStatus.UNAUTHORIZED)
          .data(null)
          .message("Redis user not found with email:" + userEmail)
          .path(request.getServletPath())
          .accessToken(null)
          .build());
    }

    User userExisting = userOptional.get();

    if(userExisting.getSecret()==null || userExisting.getSecret().isEmpty()) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(AuthResponse.builder()
          .status(HttpStatus.UNAUTHORIZED)
          .data(null)
          .message(" User secret not found" + userEmail)
          .path(request.getServletPath())
          .accessToken(null)
          .build());
    }
    System.out.println("userExisting secret:" + userExisting.getSecret());
    if(!defaultMFATokenManager.verifyTotp(numberDigits,userExisting.getSecret())){
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(AuthResponse.builder()
          .status(HttpStatus.BAD_REQUEST)
          .data(null)
          .message("Verify failure! please enter the code on your Google Authenticator App.")
          .path(request.getServletPath())
          .accessToken(null)
          .build());
    }

    userExisting.setIsUsing2FA(true);
    redisUser.setIsUsing2FA(true);
    redisDataAccess.save(redisUser);
    userDataAccess.save(userExisting);

    return ResponseEntity.status(HttpStatus.OK).body(AuthResponse.builder()
        .status(HttpStatus.OK)
        .data(null)
        .message("Enable Multi Factor Authenticate successfully!")
        .path(request.getServletPath())
        .accessToken(null)
        .build());
  }

  /*
   * Uses: Get user info from access token
   * Case: Cannot extract token from header:
   *     - Throw Error
   * Case: Cannot extract user email from token:
   *     - Throw Error
   * Case: Non-exist user:
   *     - Throw Error
   * Case: All thing good!!!
   *     - return response data
   * */
  public ResponseEntity<AuthResponse> getProfile(HttpServletRequest request, HttpServletResponse response) {
    try {
      final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
      final String jwt;
      final String userEmail;
      if (authHeader == null || !authHeader.startsWith("Bearer ")) {
        throw new ForbiddenException("token not found");
      }
      jwt = authHeader.substring(7);
      userEmail = jwtService.extractUsername(jwt);
      if (userEmail == null) throw new UnAuthenticateException("Cannot extract email from token");

      Optional<User> userOptional = userDataAccess.findByEmail(userEmail);
      if (userOptional.isEmpty()) throw new UnAuthenticateException("User not found with this token");

      return ResponseEntity.status(HttpStatus.OK).body(AuthResponse.builder()
          .status(HttpStatus.OK)
          .data(userOptional.get())
          .message("get profile successfully!")
          .path(request.getServletPath())
          .accessToken(jwtService.generateToken(userOptional.get().getEmail()))
          .build());
    } catch (ForbiddenException e) {
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.FORBIDDEN, e.getMessage());
    } catch (UnAuthenticateException | JwtException e) {
      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.UNAUTHORIZED, e.getMessage());
    } catch (RuntimeException e) {

      return AuthResponseException.responseBaseOnErrorStatus(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
    }
  }
}
