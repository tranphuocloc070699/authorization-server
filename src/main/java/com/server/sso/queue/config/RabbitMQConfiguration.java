package com.server.sso.queue.config;

import org.springframework.amqp.core.*;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RabbitMQConfiguration {

  @Value("${app.rabbitmq.exchange}")
  private String exchange;
  @Value("${app.rabbitmq.db.queue}")
  private String dbQueueName;

  @Value("${app.rabbitmq.db.routingkey}")
  private String dbRoutingkey;

  @Value("${app.rabbitmq.mail.queue}")
  private String mailQueueName;

  @Value("${app.rabbitmq.mail.routingkey}")
  private String mailRoutingkey;

  @Bean
  public TopicExchange topicExchange() {
    return new TopicExchange(exchange);
  }

  @Bean
  public Queue dbQueue() {
    return new Queue(dbQueueName);
  }

  @Bean
  public Binding dbBinding() {
    return BindingBuilder
        .bind(dbQueue())
        .to(topicExchange())
        .with(dbRoutingkey);
  }

  @Bean
  public Queue mailQueue() {
    return new Queue(mailQueueName);
  }

  @Bean
  public Binding mailBinding() {
    return BindingBuilder
        .bind(mailQueue())
        .to(topicExchange())
        .with(mailRoutingkey);
  }

  @Bean
  MessageConverter messageConverter() {
    return new Jackson2JsonMessageConverter();
  }

  @Bean
  public AmqpTemplate amqpTemplate(ConnectionFactory connectionFactory) {
    RabbitTemplate rabbitTemplate = new RabbitTemplate(connectionFactory);
    rabbitTemplate.setMessageConverter(messageConverter());
    return rabbitTemplate;

  }
}
