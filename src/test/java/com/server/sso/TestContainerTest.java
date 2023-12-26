package com.server.sso;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class TestContainerTest extends AbstractTestContainer{


  @Test
  void canStartPostgresDB() {

    assertThat(postgresqlContainer.isRunning()).isTrue();
    assertThat(postgresqlContainer.isCreated()).isTrue();

  }


}