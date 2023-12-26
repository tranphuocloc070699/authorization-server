package com.server.sso.shared;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ExtractDataTest {

  @Test
  public void testGetNameWithOAuth2User() {
    // Mock an OAuth2User for testing
    Map<String, Object> attributes = new HashMap<>();
    attributes.put("email", "test@example.com");
    OAuth2User oAuth2User = new DefaultOAuth2User(null, attributes, "email");

    Authentication authentication = new UsernamePasswordAuthenticationToken(oAuth2User, null);

    // Call the getName method and assert the result
    String result = ExtractData.getName(authentication);
    assertEquals("test@example.com", result);
  }

  @Test
  public void testGetNameWithUnsupportedAuthentication() {
    // Mock an unsupported authentication type for testing
    Authentication authentication = new UsernamePasswordAuthenticationToken("user", "password");

    // Call the getName method and assert the result
    String result = ExtractData.getName(authentication);
    assertEquals("user", result);
  }

}