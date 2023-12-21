package com.server.sso.mail;


import org.springframework.web.multipart.MultipartFile;

public interface EmailService  {
  String sendMail(String to, String subject,String confirmationLink);
}