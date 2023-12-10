package com.server.sso.auth;

import jakarta.persistence.*;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.util.Date;

@Table
@Entity(name = "users")
@Data
public class User {
  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private String id;

  @Column(nullable = false,unique = true)
  private String email;

  @Column(name = "provider_type")
  private String providerType;

  @Column
  private String password;

  @Column(nullable = false)
  private String name;

  @CreationTimestamp
  @Column(name="created_at")
  private Date createdAt;

  @UpdateTimestamp
  @Column(name = "updated_at")
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
