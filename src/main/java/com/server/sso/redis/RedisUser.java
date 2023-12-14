package com.server.sso.redis;

import com.server.sso.user.Provider;
import com.server.sso.user.Role;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
//import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.RedisHash;

import java.io.Serializable;
import java.util.Date;
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@RedisHash("User")
public class RedisUser implements Serializable {
//  private static final long serialVersionUID = 5749161485682157558L;
  @Id
  private String id;
  private String email;
  private String name;
  private Provider provider;
  private Role role;
  private Integer refreshTokenVersion ;
  private Date createdAt;
  private Date updatedAt;
}
