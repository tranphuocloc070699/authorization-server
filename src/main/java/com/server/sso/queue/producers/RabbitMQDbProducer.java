package com.server.sso.queue.producers;

import com.server.sso.user.User;
import com.server.sso.user.UserDataAccess;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RabbitMQDbProducer {
  @Value("${app.rabbitmq.exchange}")
  String exchange;

  @Value("${app.rabbitmq.db.routingkey}")
  private String routingkey;

  private final RabbitTemplate rabbitTemplate;
  private static final Logger LOGGER = LoggerFactory.getLogger(RabbitMQDbProducer.class);

  public void sendSaveUserRequestToPostgres(User user) {
    LOGGER.info(String.format("Save User To Postgresql Database: %s",user));
    rabbitTemplate.convertAndSend(exchange,routingkey,user);
  }
}
