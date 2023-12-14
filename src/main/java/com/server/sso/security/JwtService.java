package com.server.sso.security;

import com.server.sso.shared.Constant;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.*;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtService {

  private final Constant CONST;

  public String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  public String generateToken(String subject) {
    return generateToken(new HashMap<>(), subject);
  }

  public String generateToken(
      Map<String, Object> extraClaims,
      String subject
  ) {
    return buildToken(extraClaims, subject, CONST.JWT_ACCESS_TOKEN_EXPIRE);
  }

  public String generateRefreshToken(
      Integer refreshTokenVersion,
      String subject
  ) {
    Map<String,Object> map = new HashMap<>();
    map.put("refreshTokenVersion",refreshTokenVersion);
    return buildToken(map, subject, CONST.JWT_REFRESH_TOKEN_EXPIRE);
  }

  private String buildToken(
      Map<String, Object> extraClaims,
      String subject,
      long expiration
  ) {
    return Jwts
        .builder()
        .setClaims(extraClaims)
        .setSubject(subject)
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis() + expiration))
        .signWith(getSignInKey(), SignatureAlgorithm.HS256)
        .compact();
  }

  public boolean isTokenValid(String token, UserDetails userDetails) {
    final String username = extractUsername(token);
    return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
  }

  private boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());

  }

  private Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
  }

  private Claims extractAllClaims(String token) {
    SecretKey secret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(CONST.JWT_SECRET_KEY));
    return Jwts.parser().verifyWith(secret).build().parseClaimsJws(token).getBody();

  }

  private Key getSignInKey() {
    byte[] keyBytes = Decoders.BASE64.decode(CONST.JWT_SECRET_KEY);
    return Keys.hmacShaKeyFor(keyBytes);
  }

  public void writeCookie(Integer refreshTokenVersion,String subject, HttpServletResponse response) {
    String refreshToken = generateRefreshToken(refreshTokenVersion,subject);
    Cookie cookie = new Cookie(CONST.JWT_REFRESH_TOKEN_NAME, refreshToken);
    cookie.setMaxAge(CONST.JWT_REFRESH_TOKEN_EXPIRE);
    cookie.setSecure(false);
    cookie.setHttpOnly(true);
    cookie.setPath("/");
    response.addCookie(cookie);
  }

  public void removeCookie(String cookieName, HttpServletResponse response) {
    Cookie cookie = new Cookie(cookieName, null);
    cookie.setMaxAge(0);
    cookie.setSecure(false);
    cookie.setHttpOnly(true);
    cookie.setPath("/");
    response.addCookie(cookie);
  }

  public Optional<String> readServletCookie(HttpServletRequest request, String name) {
    return Arrays.stream(request.getCookies())
        .filter(cookie -> name.equals(cookie.getName()))
        .map(Cookie::getValue)
        .findAny();
  }
}
