package com.server.sso.mail;

import com.server.sso.shared.Constant;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import jakarta.mail.internet.MimeMessage;

@Service
@RequiredArgsConstructor
public class MailServiceImpl implements MailService {
  private final JavaMailSender javaMailSender;
  private final TemplateEngine templateEngine;
  private final Constant CONST;

  /*
  * Uses: Send mail to specific mail
  * */
  @Override
  public void sendMail( String to, String subject,String confirmationLink) {
    try {
      MimeMessage mimeMessage = javaMailSender.createMimeMessage();
      MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage, true);
      mimeMessageHelper.setFrom(CONST.MAIL_USERNAME);
      mimeMessageHelper.setTo(to);
      mimeMessageHelper.setSubject(subject);

      String templateName = "main-confirmation";
      String htmlContent = loadTemplate(templateName, confirmationLink,CONST.APP_DOMAIN);
      mimeMessageHelper.setText(htmlContent,true);
      javaMailSender.send(mimeMessage);

    } catch (Exception e) {
      System.err.println("[MailService-sendMail] Internal Server Error " + e.getMessage());
      throw new RuntimeException(e);
    }
  }

  /*
  * Uses: Load template from resources/templates and convert to String
  * Notes: Thymeleaf config (prefix,suffix) in Thymeleaf Configuration
  * */
  public String loadTemplate(String templateName, String confirmationLink,String serverLink) {
    Context context = new Context();
    context.setVariable("confirmationLink", confirmationLink);
    context.setVariable("serverLink", serverLink);

    try {
      return templateEngine.process(templateName, context);
    } catch (Exception e) {
      System.err.println("[MailService-loadTemplate] Internal Server Error " + e.getMessage());
      throw new RuntimeException("Error loading template", e);
    }
  }
}