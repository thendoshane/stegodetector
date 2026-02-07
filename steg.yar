rule Detect_AI_Generated_Synthetic_Payload {
    meta:
        description = "Detects the specific AI-generated synthetic payload for research validation"
        author = "Siphuma Thendo (Student: 217001561)"
        reference = "Thesis Phase 2: Signature Development"
        severity = "High"
        
    strings:
        // Detects the specific AI tag used in the payload
        $ai_tag = "AI_SYNTH_THREAT" ascii
        
        // Detects the obfuscation wrapper often used by AI code generators
        $obfuscation = "exec(b64decode" ascii

    condition:
        // Trigger if EITHER the specific tag OR the obfuscation pattern is found
        $ai_tag or $obfuscation
}