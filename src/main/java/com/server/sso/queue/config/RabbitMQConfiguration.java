package com.server.sso.queue.config;

import com.server.sso.shared.Constant;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.core.*;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class RabbitMQConfiguration {
  private final Constant CONST;

  /*
  * TOPIC
  * */
  @Bean
  public TopicExchange topicExchange() {
    return new TopicExchange(CONST.RABBITMQ_EXCHANGE);
  }


  /*
  * POSTGRESQL DATABASE
  * */
  @Bean
  public Queue dbQueue() {
    return new Queue(CONST.RABBITMQ_DB_QUEUE_NAME);
  }
  @Bean
  public Binding dbBinding() {
    return BindingBuilder
        .bind(dbQueue())
        .to(topicExchange())
        .with(CONST.RABBITMQ_DB_ROUTING_KEY);
  }

  /*
  * MAIL
  * */
  @Bean
  public Queue mailQueue() {
    return new Queue(CONST.RABBITMQ_MAIL_QUEUE_NAME);
  }
  @Bean
  public Binding mailBinding() {
    return BindingBuilder
        .bind(mailQueue())
        .to(topicExchange())
        .with(CONST.RABBITMQ_MAIL_ROUTING_KEY);
  }


  /*
  * Uses: Implement Json Converter to rabbitmq (default only send String)
  * */
  @Bean
  MessageConverter messageConverter() {
    return new Jackson2JsonMessageConverter();
  }

  /*
   * Uses: Set Json Converter to rabbitmq
   * */
  @Bean
  public AmqpTemplate amqpTemplate(ConnectionFactory connectionFactory) {
    RabbitTemplate rabbitTemplate = new RabbitTemplate(connectionFactory);
    rabbitTemplate.setMessageConverter(messageConverter());
    return rabbitTemplate;

  }
}
