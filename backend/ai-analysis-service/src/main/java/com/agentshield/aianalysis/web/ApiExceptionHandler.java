package com.agentshield.aianalysis.web;

import java.time.Instant;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

@RestControllerAdvice
public class ApiExceptionHandler {
    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<ApiError> validation(MethodArgumentNotValidException ex) { return response(HttpStatus.BAD_REQUEST,"Request validation failed"); }
    @ExceptionHandler(HttpMessageNotReadableException.class)
    ResponseEntity<ApiError> unreadable(HttpMessageNotReadableException ex) {
        if(hasSizeLimit(ex)) return response(HttpStatus.PAYLOAD_TOO_LARGE,"Request body exceeds the configured limit");
        return response(HttpStatus.BAD_REQUEST,"Request body is invalid");
    }
    @ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<ApiError> status(ResponseStatusException ex) {
        HttpStatus status=HttpStatus.valueOf(ex.getStatusCode().value());
        String message=status.is4xxClientError()?ex.getReason():"Request could not be completed";
        return response(status,message==null?"Request could not be completed":message);
    }
    @ExceptionHandler(Exception.class)
    ResponseEntity<ApiError> unexpected(Exception ex) { return response(HttpStatus.INTERNAL_SERVER_ERROR,"Analysis could not be completed"); }
    private ResponseEntity<ApiError> response(HttpStatus s,String m) { return ResponseEntity.status(s).body(new ApiError(Instant.now(),s.value(),s.getReasonPhrase(),m)); }
    private boolean hasSizeLimit(Throwable t) { for(Throwable x=t;x!=null;x=x.getCause()) if(x instanceof AnalysisRequestGuardFilter.RequestBodyLimitExceededException)return true; return false; }
}
