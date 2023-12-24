package com.server.sso.user;

import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Table
@Entity(name = "tbl_user")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User implements UserDetails {
  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private String id;

  @Column(nullable = false,unique = true)
  private String email;
  @JsonIgnore
  @Column
  private String password;

  @Column(nullable = false)
  private String name;

  @Enumerated(EnumType.STRING)
  private Provider provider;

  @Enumerated(EnumType.STRING)
  private Role role;

  @Column(columnDefinition = "BOOLEAN DEFAULT false")
  private Boolean isUsing2FA;

  @Column
  private String secret;

  @CreationTimestamp
  @Column(name="created_at")
  private Date createdAt;

  @UpdateTimestamp
  @Column(name = "updated_at")
  private Date updatedAt;

  @JsonIgnore
  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    if (role == null) {
      return List.of(new SimpleGrantedAuthority(Role.USER.name()));
    }

    return role.getAuthorities();
  }

  @Override
  public String getPassword() {
    return password;
  }

  @Override
  public String getUsername() {
    return email;
  }
  @JsonIgnore
  @Override
  public boolean isAccountNonExpired() {
    return true;
  }
  @JsonIgnore
  @Override
  public boolean isAccountNonLocked() {
    return true;
  }
  @JsonIgnore
  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }
  @JsonIgnore
  @Override
  public boolean isEnabled() {
    return true;
  }


//  @PrePersist
//  protected void onCreate() {
//    createdAt = new Date();
//  }
//
//  @PreUpdate
//  protected void onUpdate() {
//    if (isUsing2FA) {
//      secret = RandomData.generateRandomBase32();
//    }
//  }

}
