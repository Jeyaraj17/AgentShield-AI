package com.agentshield.aianalysis.web;

import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ReadListener;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class AnalysisRequestGuardFilter extends OncePerRequestFilter {
    private record Window(long startedAt,AtomicInteger count) { }
    private final ConcurrentHashMap<String,Window> windows=new ConcurrentHashMap<>();
    private final long maxBytes,windowMillis; private final int limit;
    public AnalysisRequestGuardFilter(@Value("${agentshield.analysis.request.max-bytes:1048576}") long maxBytes,
            @Value("${agentshield.analysis.rate-limit.requests-per-minute:120}") int limit,
            @Value("${agentshield.analysis.rate-limit.window:1m}") Duration window) {
        if(maxBytes<1024||limit<1||window.isNegative()||window.isZero()) throw new IllegalArgumentException("Invalid analysis request guard configuration");
        this.maxBytes=maxBytes;this.limit=limit;this.windowMillis=window.toMillis();
    }
    @Override protected boolean shouldNotFilter(HttpServletRequest request) { return !request.getRequestURI().startsWith("/api/v1/analysis/"); }
    @Override protected void doFilterInternal(HttpServletRequest request,HttpServletResponse response,FilterChain chain) throws ServletException,IOException {
        if(request.getContentLengthLong()>maxBytes) { ApiErrorWriter.write(response,org.springframework.http.HttpStatus.PAYLOAD_TOO_LARGE,"Request body exceeds the configured limit"); return; }
        long now=System.currentTimeMillis(); String key=request.getRemoteAddr()+":"+request.getRequestURI();
        Window window=windows.compute(key,(k,old)->old==null||now-old.startedAt()>=windowMillis?new Window(now,new AtomicInteger()):old);
        if(window.count().incrementAndGet()>limit) { response.setHeader("Retry-After",Long.toString(Math.max(1,windowMillis/1000)));ApiErrorWriter.write(response,org.springframework.http.HttpStatus.TOO_MANY_REQUESTS,"Request rate limit exceeded");return; }
        HttpServletRequest guarded=request.getContentLengthLong()<0?new SizeLimitedRequest(request,maxBytes):request;
        chain.doFilter(guarded,response);
        if(windows.size()>10000) windows.entrySet().removeIf(e->now-e.getValue().startedAt()>windowMillis*2);
    }

    static final class RequestBodyLimitExceededException extends IOException {
        RequestBodyLimitExceededException(){super("Request body limit exceeded");}
    }
    private static final class SizeLimitedRequest extends HttpServletRequestWrapper {
        private final long maximum; private ServletInputStream wrapped;
        SizeLimitedRequest(HttpServletRequest request,long maximum){super(request);this.maximum=maximum;}
        @Override public ServletInputStream getInputStream() throws IOException {
            if(wrapped==null) {
                ServletInputStream original=super.getInputStream();
                wrapped=new ServletInputStream(){long count;
                    @Override public int read() throws IOException {
                        int value=original.read();if(value!=-1&&++count>maximum)throw new RequestBodyLimitExceededException();return value;
                    }
                    @Override public int read(byte[] b,int off,int len)throws IOException {
                        int n=original.read(b,off,len);if(n>0){count+=n;if(count>maximum)throw new RequestBodyLimitExceededException();}return n;
                    }
                    @Override public boolean isFinished(){return original.isFinished();}
                    @Override public boolean isReady(){return original.isReady();}
                    @Override public void setReadListener(ReadListener listener){original.setReadListener(listener);}
                };
            }
            return wrapped;
        }
        @Override public BufferedReader getReader() throws IOException {
            String encoding=getCharacterEncoding();return new BufferedReader(new InputStreamReader(getInputStream(),encoding==null?Charset.defaultCharset():Charset.forName(encoding)));
        }
    }
}
