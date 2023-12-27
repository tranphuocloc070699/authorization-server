package com.server.sso.errors;

import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;

@Controller
public class CustomErrorController implements ErrorController {
  /*
  * Scope: Private [Authenticated]
  * Uses: Custom error page
  * */
  @RequestMapping("/error")
  public String handleError(HttpServletRequest request, Model model) {
    Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
    String errorMessage = (String) request.getAttribute(RequestDispatcher.ERROR_MESSAGE);
    if (status != null) {
      Integer statusCode = Integer.valueOf(status.toString());
      model.addAttribute("statusCode",statusCode);
    }
    if (errorMessage != null) {
      model.addAttribute("errorMessage",errorMessage);
    }
    return "error";

  }
}