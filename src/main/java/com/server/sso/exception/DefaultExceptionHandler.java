package com.server.sso.exception;

import com.server.sso.shared.ResponseObject;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.validation.BindException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;
import org.springframework.validation.ObjectError;
import java.util.ArrayList;
import java.util.List;


@ControllerAdvice
public class DefaultExceptionHandler {

  @ExceptionHandler(MethodArgumentNotValidException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public String handleBindException(BindException e) {
    // Trả về message của lỗi đầu tiên
    String errorMessage = "Request invalid";
    if (e.getBindingResult().hasErrors()) {
      errorMessage = e.getBindingResult().getAllErrors().get(0).getDefaultMessage();
    }
    return errorMessage;
  }
}


//@ControllerAdvice
//public class DefaultExceptionHandler  extends ResponseEntityExceptionHandler {
//  @Override
//  protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex, HttpHeaders headers,
//                                                                HttpStatusCode status, WebRequest request) {
//    List<String> errors = new ArrayList<String>();
//    String path = request.getDescription(false);
//    for (FieldError error : ex.getBindingResult().getFieldErrors()) {
//      errors.add(error.getField() + ": " + error.getDefaultMessage());
//    }
//    for (ObjectError error : ex.getBindingResult().getGlobalErrors()) {
//      errors.add(error.getObjectName() + ": " + error.getDefaultMessage());
//    }
//
//    ResponseObject apiError = ResponseObject.builder()
//        .status(HttpStatus.BAD_REQUEST)
//        .data(errors)
//        .message("Validate fail")
//        .path(path.substring(4))
//        .build();
//
//    return new ResponseEntity<>(apiError,headers,status);
//  }
//}

