package com.server.sso.mail;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import jakarta.mail.internet.MimeMessage;

@Service
public class EmailServiceImpl implements EmailService {

  @Value("${spring.mail.username}")
  private String fromEmail;

  @Autowired
  private JavaMailSender javaMailSender;

  @Autowired
  TemplateEngine templateEngine;

  @Override
  public String sendMail( String to, String subject,String confirmationLink) {
    try {
      MimeMessage mimeMessage = javaMailSender.createMimeMessage();
      MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage, true);
      mimeMessageHelper.setFrom(fromEmail);
      mimeMessageHelper.setTo(to);
      mimeMessageHelper.setSubject(subject);
      String htmlContent = loadTemplate("mail-confirmation", confirmationLink,"http://localhost:8080");
      mimeMessageHelper.setText(htmlContent,true);
      javaMailSender.send(mimeMessage);
      return "mail send";
    } catch (Exception e) {
      throw new RuntimeException(e);
    }


  }

  public String loadTemplate(String templateName, String confirmationLink,String serverLink) {
    Context context = new Context();
    context.setVariable("confirmationLink", confirmationLink);
    context.setVariable("serverLink", serverLink);

    try {
      return templateEngine.process(templateName, context);
    } catch (Exception e) {
      throw new RuntimeException("Error loading template", e);
    }
  }
}