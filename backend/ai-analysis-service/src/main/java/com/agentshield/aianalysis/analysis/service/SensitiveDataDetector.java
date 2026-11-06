package com.agentshield.aianalysis.analysis.service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class SensitiveDataDetector {
    private record Rule(String category,Pattern pattern) { }
    private final List<Rule> rules;
    public SensitiveDataDetector(@Value("${agentshield.analysis.sensitive.patterns:}") String configured) {
        List<Rule> values=new ArrayList<>();
        values.add(rule("EMAIL","(?i)\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b"));
        values.add(rule("BEARER_TOKEN","(?i)\\bBearer\\s+[A-Za-z0-9._~+/-]{12,}={0,2}"));
        values.add(rule("ACCESS_TOKEN","(?i)\\b(?:access[_ -]?token|token)\\s*[:=]\\s*[A-Za-z0-9._~+/-]{12,}={0,2}"));
        values.add(rule("JWT","\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b"));
        values.add(rule("API_KEY","(?i)\\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|api[_-]?key\\s*[:=]\\s*[A-Za-z0-9_-]{12,})\\b"));
        values.add(rule("PASSWORD","(?i)\\b(?:password|passwd|secret)\\s*[:=]\\s*[^\\s,;]{4,}"));
        if(configured!=null&&!configured.isBlank()) for(String entry:configured.split(";")) {
            String[] parts=entry.split("=",2); if(parts.length!=2||!parts[0].matches("[A-Z][A-Z0-9_]{1,39}")) throw new IllegalArgumentException("AI_SENSITIVE_PATTERNS entries must be CATEGORY=REGEX");
            values.add(rule(parts[0],parts[1]));
        }
        rules=List.copyOf(values);
    }
    public Detection detectAndRedact(String text) {
        String redacted=text; List<Finding> findings=new ArrayList<>();
        for(Rule rule:rules) {
            Matcher matcher=rule.pattern().matcher(redacted); int count=0; StringBuffer out=new StringBuffer();
            while(matcher.find()) { count++; matcher.appendReplacement(out,Matcher.quoteReplacement("[REDACTED:"+rule.category()+"]")); }
            matcher.appendTail(out); if(count>0) { redacted=out.toString(); findings.add(new Finding(rule.category(),count)); }
        }
        return new Detection(redacted,List.copyOf(findings));
    }
    private static Rule rule(String category,String regex) { try { return new Rule(category,Pattern.compile(regex)); } catch(RuntimeException ex) { throw new IllegalArgumentException("Invalid sensitive data pattern for "+category); } }
    public record Finding(String category,int count) { }
    public record Detection(String redactedText,List<Finding> findings) { }
}
