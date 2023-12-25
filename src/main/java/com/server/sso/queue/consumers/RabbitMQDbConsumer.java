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
  private final UserDataAccess userDataAccess;

  /*
   * Uses: Receive user entity from producers and save to database (postgresql)
   * */
  @RabbitListener(queues = {"${app.rabbitmq.db.queue}"})
  public void saveUserToPostgres (User user) {
    userDataAccess.save(user);
  }
}
