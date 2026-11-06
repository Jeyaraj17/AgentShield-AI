package com.agentshield.aianalysis.analysis.service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class PromptInjectionDetector {
    private record Signal(String category,Pattern pattern,int score,String explanation) { }
    private final List<Signal> signals=List.of(
            signal("INSTRUCTION_OVERRIDE","(?i)\\b(ignore|disregard|override|forget)\\b.{0,60}\\b(previous|above|system|developer|all)\\b.{0,30}\\b(instruction|prompt|rule)s?\\b",45,"Attempts to replace prior or higher-priority instructions."),
            signal("JAILBREAK","(?i)\\b(DAN|do anything now|jailbreak|developer mode|no restrictions|bypass safety)\\b",40,"Contains wording commonly used in jailbreak attempts."),
            signal("SECRET_EXTRACTION","(?i)\\b(reveal|print|show|repeat|dump)\\b.{0,50}\\b(system prompt|hidden instruction|secret|credential|api key)\\b",35,"Attempts to extract hidden instructions or secrets."),
            signal("INSTRUCTION_CHAINING","(?i)\\b(first|step 1)\\b.{0,100}\\b(ignore|bypass|override)\\b.{0,100}\\b(then|after that|next)\\b",35,"Chains steps that include instruction bypassing."),
            signal("EMBEDDED_INSTRUCTION","(?i)(<\\s*system\\s*>|\\[system\\]|\\[developer\\]|BEGIN (SYSTEM|DEVELOPER) INSTRUCTIONS)",25,"Contains instruction-like content embedded in user data."));
    public Result analyze(String prompt) {
        List<String> categories=new ArrayList<>(),explanations=new ArrayList<>(); int score=0;
        for(Signal signal:signals) if(signal.pattern().matcher(prompt).find()) { categories.add(signal.category()); explanations.add(signal.explanation()); score=Math.min(100,score+signal.score()); }
        return new Result(categories.isEmpty()?"NONE":categories.getFirst(),List.copyOf(categories),score,
                categories.isEmpty()?"No configured prompt-injection indicators matched; this heuristic is not a guarantee of safety.":String.join(" ",explanations)+" Detection is heuristic, not proof of malicious intent.");
    }
    private static Signal signal(String c,String regex,int score,String explanation){return new Signal(c,Pattern.compile(regex),score,explanation);}
    public record Result(String category,List<String> categories,int riskScore,String explanation) { }
}
