package com.agentshield.aianalysis.analysis.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class HallucinationEvaluator {
    private static final Pattern SENTENCE=Pattern.compile("(?<=[.!?])\\s+|\\n+");
    private static final Pattern WORD=Pattern.compile("[\\p{L}\\p{N}]{3,}");
    private static final Set<String> NEGATIONS=Set.of("not","never","no","without","cannot","didnt","doesnt","isnt","wasnt");
    private static final List<List<String>> OPPOSITES=List.of(List.of("increase","decrease"),List.of("allow","deny"),List.of("allows","denies"),List.of("allowed","denied"),List.of("true","false"),List.of("safe","unsafe"),List.of("supported","unsupported"),List.of("present","absent"));
    public Result evaluate(String response,List<String> evidence) {
        List<String> supported=new ArrayList<>(),unsupported=new ArrayList<>(),conflicting=new ArrayList<>();
        List<Set<String>> evidenceTerms=evidence.stream().map(this::terms).toList();
        for(String sentence:SENTENCE.split(response)) {
            String claim=sentence.trim(); if(claim.isBlank()) continue; Set<String> words=terms(claim); double best=0; Set<String> bestEvidence=Set.of();
            for(Set<String> source:evidenceTerms) { long overlap=words.stream().filter(source::contains).count(); double ratio=words.isEmpty()?0:(double)overlap/words.size(); if(ratio>best){best=ratio;bestEvidence=source;} }
            if(best>=0.45&&contradicts(words,bestEvidence)) conflicting.add(claim);
            else if(best>=0.55) supported.add(claim); else unsupported.add(claim);
        }
        int total=supported.size()+unsupported.size()+conflicting.size();
        int score=total==0?0:(int)Math.round((100.0*unsupported.size()+100.0*conflicting.size()+20.0*supported.size())/total);
        return new Result(List.copyOf(supported),List.copyOf(unsupported),List.copyOf(conflicting),score,
                "Heuristic overlap and contradiction checks against supplied evidence; this estimates risk and cannot determine factuality with certainty.");
    }
    private Set<String> terms(String text) { var matcher=WORD.matcher(text.toLowerCase(Locale.ROOT));var out=new java.util.HashSet<String>();while(matcher.find())out.add(matcher.group());return out; }
    private boolean contradicts(Set<String> claim,Set<String> evidence) {
        boolean claimNeg=claim.stream().anyMatch(NEGATIONS::contains),evidenceNeg=evidence.stream().anyMatch(NEGATIONS::contains);
        if(claimNeg!=evidenceNeg&&claim.stream().anyMatch(evidence::contains)) return true;
        for(List<String> pair:OPPOSITES) if((claim.contains(pair.get(0))&&evidence.contains(pair.get(1)))||(claim.contains(pair.get(1))&&evidence.contains(pair.get(0)))) return true;
        return false;
    }
    public record Result(List<String> supportedClaims,List<String> unsupportedClaims,List<String> conflictingClaims,int riskScore,String explanation) { }
}
