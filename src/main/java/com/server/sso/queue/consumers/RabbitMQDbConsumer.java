package com.server.sso.queue.consumers;

import com.server.sso.user.User;
import com.server.sso.user.UserDataAccess;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RabbitMQDbConsumer {
  private static final Logger LOGGER = LoggerFactory.getLogger(RabbitMQDbConsumer.class);
  private final UserDataAccess userDataAccess;
  @RabbitListener(queues = {"${app.rabbitmq.db.queue}"})
  public void saveUserToPostgres (User user) {
    LOGGER.info(String.format("receive user -> %s",user.toString()));
    userDataAccess.save(user);
  }
}
