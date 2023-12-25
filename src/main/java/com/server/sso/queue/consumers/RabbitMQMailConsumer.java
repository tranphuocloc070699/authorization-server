package com.server.sso.queue.consumers;

import com.server.sso.mail.MailServiceImpl;
import com.server.sso.mail.MailSenderDto;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RabbitMQMailConsumer {
  private final MailServiceImpl emailService;


  /*
   * Uses: Receive mail entity from producers and send mail to specific user email
   * */
  @RabbitListener(queues = {"${app.rabbitmq.mail.queue}"})
  public void sendMail (MailSenderDto dto) {
    emailService.sendMail(dto.getTo(),dto.getSubject(), dto.getConfirmationLink());
  }
}
