package com.server.sso.queue.consumers;

import com.server.sso.mail.EmailServiceImpl;
import com.server.sso.mail.MailSenderDto;
import com.server.sso.queue.producers.RabbitMQMailProducer;
import com.server.sso.user.User;
import com.server.sso.user.UserDataAccess;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RabbitMQMailConsumer {
  private static final Logger LOGGER = LoggerFactory.getLogger(RabbitMQMailConsumer.class);
  private final EmailServiceImpl emailService;
  @RabbitListener(queues = {"${app.rabbitmq.mail.queue}"})
  public void sendMail (MailSenderDto dto) {
    emailService.sendMail(dto.getTo(),dto.getSubject(), dto.getConfirmationLink());
    LOGGER.info(String.format("Receive Mail Sending Request To -> %s",dto.toString()));

  }
}
