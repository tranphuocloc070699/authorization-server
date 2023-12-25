package com.server.sso.redis;

import java.io.Serializable;
import java.util.Date;

//import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.RedisHash;

import com.server.sso.user.Provider;
import com.server.sso.user.Role;

import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@RedisHash(value = "User")
public class RedisUser implements Serializable {
  @Id
  private String id;
  private String email;
  private String name;
  private String password;
  private Provider provider;
  private Role role;
  private Integer refreshTokenVersion ;
  private Boolean isUsing2FA;
  private String secret;
  private Date createdAt;
  private Date updatedAt;
}
