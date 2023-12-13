package com.server.sso.auth;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.Collection;
import java.util.Date;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@RedisHash("User")
public class RedisUser implements Serializable {
  @Id
  private String id;
  private String email;
  private String name;
  private Provider provider;
  private Role role;
  private Date createdAt;
  private Date updatedAt;
//  @PrePersist
//  protected void onCreate() {
//    created = new Date();
//  }
//
//  @PreUpdate
//  protected void onUpdate() {
//    updated = new Date();
//  }

}
