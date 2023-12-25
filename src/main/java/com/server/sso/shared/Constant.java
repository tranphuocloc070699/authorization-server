package com.server.sso.shared;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class Constant {
  /*
  * Json Web Token
  */
  @Value("${application.security.jwt.refresh-token.name}")
  public String JWT_REFRESH_TOKEN_NAME= "";
  @Value("${application.security.jwt.secret-key}")
  public String JWT_SECRET_KEY;
  @Value("${application.security.jwt.expiration}")
  public Integer JWT_ACCESS_TOKEN_EXPIRE;
  @Value("${application.security.jwt.refresh-token.expiration}")
  public Integer JWT_REFRESH_TOKEN_EXPIRE;

  /*
   * RabbitMQ
   */
  @Value("${app.rabbitmq.exchange}")
  public String RABBITMQ_EXCHANGE;
  @Value("${app.rabbitmq.db.queue}")
  public String RABBITMQ_DB_QUEUE_NAME;
  @Value("${app.rabbitmq.db.routing-key}")
  public String RABBITMQ_DB_ROUTING_KEY;
  @Value("${app.rabbitmq.mail.queue}")
  public String RABBITMQ_MAIL_QUEUE_NAME;
  @Value("${app.rabbitmq.mail.routing-key}")
  public String RABBITMQ_MAIL_ROUTING_KEY;

  /*
  * Redis
  */
  @Value("{app.redis.host-name}")
  public String REDIS_HOST_NAME;
  @Value("{app.redis.port}")
  public Integer REDIS_PORT;

  /*
  * Mail
  */
  @Value("${spring.mail.username}")
  public String MAIL_USERNAME;

  /*
   * APP
   */
  @Value("${app.domain}")
  public String APP_DOMAIN;
  @Value("${app.2fa.label}")
  public String APP_2FA_LABEL;

  @Value("${app.2fa.issuer}")
  public String APP_2FA_ISSUER;


}
