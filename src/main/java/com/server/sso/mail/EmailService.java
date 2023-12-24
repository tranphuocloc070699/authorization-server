package com.server.sso.mail;

public interface EmailService  {
  String sendMail(String to, String subject,String confirmationLink);
}