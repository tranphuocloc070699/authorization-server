package com.server.sso.mail;

public interface MailService {
  void sendMail(String to, String subject,String confirmationLink);
}