package com.server.sso.queue.producers;

import com.server.sso.mail.MailSenderDto;
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
  @Value("${app.rabbitmq.exchange}")
  String exchange;

  @Value("${app.rabbitmq.mail.routingkey}")
  private String routingkey;

  private final RabbitTemplate rabbitTemplate;
  private static final Logger LOGGER = LoggerFactory.getLogger(RabbitMQMailProducer.class);

  public void sendMailRequest(MailSenderDto dto) {
    LOGGER.info(String.format("Sending Mail To: %s",dto.getTo()));
    rabbitTemplate.convertAndSend(exchange,routingkey,dto);
  }
}
