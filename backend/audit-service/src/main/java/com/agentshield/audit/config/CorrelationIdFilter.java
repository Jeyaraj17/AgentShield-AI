package com.agentshield.audit.config;

import java.io.IOException;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class CorrelationIdFilter extends OncePerRequestFilter {
    public static final String HEADER="X-Correlation-ID";
    @Override protected void doFilterInternal(HttpServletRequest request,HttpServletResponse response,FilterChain chain) throws ServletException,IOException {
        String incoming=request.getHeader(HEADER);String id;
        try{id=incoming==null?UUID.randomUUID().toString():UUID.fromString(incoming).toString();}catch(IllegalArgumentException ex){id=UUID.randomUUID().toString();}
        MDC.put("correlationId",id);response.setHeader(HEADER,id);
        try{chain.doFilter(request,response);}finally{MDC.remove("correlationId");}
    }
}
