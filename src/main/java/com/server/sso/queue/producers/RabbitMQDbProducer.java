package com.server.sso.queue.producers;

import com.server.sso.shared.Constant;
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

  private final Constant CONST;
  private final RabbitTemplate rabbitTemplate;

  /*
   * Uses: Sending user entity to RabbitMQ Broker (Consumer save this user to postgresql database)
   * */
  public void sendSaveUserRequestToPostgres(User user) {
    rabbitTemplate.convertAndSend(CONST.RABBITMQ_EXCHANGE,CONST.RABBITMQ_DB_ROUTING_KEY,user);
  }
}
