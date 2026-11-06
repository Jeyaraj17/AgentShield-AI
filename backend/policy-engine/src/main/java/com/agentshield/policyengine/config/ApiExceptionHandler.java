package com.agentshield.policyengine.config;

import java.net.URI;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import com.agentshield.policyengine.policy.service.InvalidPolicyException;
import com.agentshield.policyengine.policy.service.PolicyNotFoundException;

@RestControllerAdvice
public class ApiExceptionHandler {
    @ExceptionHandler(PolicyNotFoundException.class)
    ProblemDetail notFound(PolicyNotFoundException ex) { return problem(HttpStatus.NOT_FOUND,"Policy not found"); }
    @ExceptionHandler({InvalidPolicyException.class,MethodArgumentNotValidException.class,org.springframework.http.converter.HttpMessageNotReadableException.class})
    ProblemDetail badRequest(Exception ex) { return problem(HttpStatus.BAD_REQUEST,"Request is invalid"); }
    private static ProblemDetail problem(HttpStatus status,String detail) {
        ProblemDetail pd=ProblemDetail.forStatusAndDetail(status,detail); pd.setType(URI.create("about:blank")); pd.setTitle(status.getReasonPhrase()); return pd;
    }
}
