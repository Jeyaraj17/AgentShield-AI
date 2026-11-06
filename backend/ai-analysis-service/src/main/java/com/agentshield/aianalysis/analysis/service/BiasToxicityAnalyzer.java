package com.agentshield.aianalysis.analysis.service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class BiasToxicityAnalyzer {
    private record Rule(String category,Pattern pattern,int score,String explanation) { }
    private final List<Rule> rules;
    public BiasToxicityAnalyzer(@Value("${agentshield.analysis.bias-toxicity.rules:}") String configured) {
        List<Rule> list=new ArrayList<>();
        list.add(rule("HARASSMENT","(?i)\\b(kill yourself|you should die|go die)\\b",70,"Contains a direct self-harm or death-directed attack."));
        list.add(rule("INSULT","(?i)\\b(idiot|stupid|moron|worthless)\\b",35,"Contains personal insult wording."));
        list.add(rule("THREAT","(?i)\\b(i will (hurt|kill|attack)|threaten to)\\b",60,"Contains an explicit threat pattern."));
        list.add(rule("DISCRIMINATORY_GENERALIZATION","(?i)\\b(all|those|these)\\s+(women|men|immigrants|refugees|disabled people|older people|young people|muslims|christians|jews)\\b.{0,60}\\b(inferior|lazy|criminal|stupid|dangerous|unfit|worthless)\\b",65,"Contains a broad negative generalization about a demographic group."));
        if(configured!=null&&!configured.isBlank()) for(String entry:configured.split(";")) {
            String[] p=entry.split("=",2);if(p.length!=2||!p[0].matches("[A-Z][A-Z0-9_]{1,39}"))throw new IllegalArgumentException("AI_BIAS_TOXICITY_RULES entries must be CATEGORY=REGEX");
            list.add(rule(p[0],p[1],40,"Matched a configured harmful-output rule."));
        }
        rules=List.copyOf(list);
    }
    public Result analyze(String text) {
        List<String> categories=new ArrayList<>(),details=new ArrayList<>();int score=0;
        for(Rule r:rules)if(r.pattern().matcher(text).find()){categories.add(r.category());details.add(r.explanation());score=Math.max(score,r.score());}
        return new Result(List.copyOf(categories),score,details.isEmpty()?"No configured harmful-output rule matched; rule-based results can miss context and nuance.":String.join(" ",details)+" Classification is heuristic and may be incomplete.");
    }
    private static Rule rule(String c,String p,int score,String explanation){try{return new Rule(c,Pattern.compile(p),score,explanation);}catch(RuntimeException ex){throw new IllegalArgumentException("Invalid configured bias/toxicity rule for "+c);}}
    public record Result(List<String> categories,int riskScore,String explanation) { }
}
