package com.server.sso.queue.producers;

import com.server.sso.mail.MailSenderDto;
import com.server.sso.shared.Constant;
import com.server.sso.user.User;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class RabbitMQMailProducer {

  private final Constant CONST;
  private final RabbitTemplate rabbitTemplate;

  /*
   * Uses: Sending mail dto to RabbitMQ Broker (Consumer send mail to specific mail)
   * */
  public void sendMailRequest(MailSenderDto dto) {
    rabbitTemplate.convertAndSend(CONST.RABBITMQ_EXCHANGE,CONST.RABBITMQ_MAIL_ROUTING_KEY,dto);
  }
}
