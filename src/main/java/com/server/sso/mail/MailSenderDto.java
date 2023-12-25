package com.server.sso.mail;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class MailSenderDto {
  private String to;
  private String subject;
  private String confirmationLink;
}
