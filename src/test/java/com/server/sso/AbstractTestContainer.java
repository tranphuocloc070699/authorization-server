package com.server.sso;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
@Testcontainers
public abstract class AbstractTestContainer {
  @BeforeAll
  static void beforeAll() {
    Flyway flyway = Flyway.configure().dataSource(
        postgresqlContainer.getJdbcUrl(),
        postgresqlContainer.getUsername(),
        postgresqlContainer.getPassword()
    ).load();
    flyway.migrate();
  }
  @Container
  protected static final PostgreSQLContainer<?> postgresqlContainer =
      new PostgreSQLContainer<>("postgres:latest")
          .withDatabaseName("sso-unit-test")
          .withUsername("your-username")
          .withPassword("password");

  @DynamicPropertySource
  private static void registerDataSourceProperties(DynamicPropertyRegistry registry){
    registry.add(
        "spring.datasource.url",
        postgresqlContainer::getJdbcUrl
    );
    registry.add(
        "spring.datasource.username",
        postgresqlContainer::getUsername
    );
    registry.add(
        "spring.datasource.password",
        postgresqlContainer::getPassword
    );
    System.out.println("Url:" + postgresqlContainer.getJdbcUrl());
    System.out.println("Username:" + postgresqlContainer.getUsername());
    System.out.println("Password:" + postgresqlContainer.getPassword());
  }


}