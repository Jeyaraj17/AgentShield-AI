package com.agentshield.runtimesecurity.config;

import java.net.URI;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import com.agentshield.runtimesecurity.runtime.service.RuntimeExceptions.AccessDenied;
import com.agentshield.runtimesecurity.runtime.service.RuntimeExceptions.ResourceNotFound;

@RestControllerAdvice
public class ApiExceptionHandler {
    @ExceptionHandler(ResourceNotFound.class) ProblemDetail notFound() { return problem(HttpStatus.NOT_FOUND,"Resource not found"); }
    @ExceptionHandler(AccessDenied.class) ProblemDetail forbidden() { return problem(HttpStatus.FORBIDDEN,"Access denied"); }
    @ExceptionHandler({MethodArgumentNotValidException.class,org.springframework.http.converter.HttpMessageNotReadableException.class})
    ProblemDetail invalidRequest(Exception ex) { return problem(HttpStatus.BAD_REQUEST,"Request is invalid"); }
    private static ProblemDetail problem(HttpStatus status,String detail) {
        ProblemDetail result=ProblemDetail.forStatusAndDetail(status,detail); result.setType(URI.create("about:blank")); result.setTitle(status.getReasonPhrase()); return result;
    }
}
