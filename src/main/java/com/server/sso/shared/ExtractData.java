package com.server.sso.shared;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Optional;

public class ExtractData {
  public static String getName(Authentication authentication) {
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
}
