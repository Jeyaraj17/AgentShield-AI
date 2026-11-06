package com.agentshield.aianalysis.web;

import java.io.IOException;
import java.time.Instant;
import org.springframework.http.HttpStatus;
import jakarta.servlet.http.HttpServletResponse;

public final class ApiErrorWriter {
    private ApiErrorWriter() { }
    public static void write(HttpServletResponse response,HttpStatus status,String message) throws IOException {
        response.setStatus(status.value());response.setCharacterEncoding("UTF-8");response.setContentType("application/json");
        response.getWriter().write("{\"timestamp\":\""+Instant.now()+"\",\"status\":"+status.value()+",\"error\":\""+status.getReasonPhrase()+"\",\"message\":\""+message+"\"}");
    }
}
