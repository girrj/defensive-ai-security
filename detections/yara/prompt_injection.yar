/*
   Indirect prompt injection in documents, emails, web pages, and tool output.

   Use cases:
     - Scan content BEFORE it reaches an LLM or agent (RAG ingestion, email
       triage, browsing or fetch tools, MCP tool responses).
     - Sweep a mailbox export, document share, or web crawl during an
       investigation into an AI assistant that misbehaved.

   These rules look for text aimed at an AI model rather than a human reader:
   instruction-override phrasing, instructions hidden from humans (HTML
   comments, invisible styling), and characters people can't see (Unicode
   tag characters and dense zero-width runs).

   Expected false positives: security training material, research papers,
   and articles ABOUT prompt injection (including this repository). Exclude
   known documentation paths, or route hits to review rather than blocking.

   MITRE ATLAS: AML.T0051.001 (indirect prompt injection), AML.T0068 (LLM
   prompt obfuscation). OWASP LLM Top 10 2026: LLM01. OWASP Agentic 2026: ASI01.

   Author: girrj   License: MIT
*/

rule PromptInjection_Instruction_Override
{
    meta:
        description = "Phrasing that tries to override an AI model's instructions"
        author      = "girrj"
        date        = "2026-11-14"
        atlas       = "AML.T0051.001"
        owasp_llm   = "LLM01:2026"
        confidence  = "medium"

    strings:
        $ov1 = /(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+|your\s+)?(previous|prior|above|earlier|existing|original)\s+(instructions|prompts?|rules|directions|guidelines)/ nocase ascii wide
        $ov2 = /(new|updated|real|actual)\s+(system\s+)?instructions\s*:/ nocase ascii wide
        $ov3 = /you\s+are\s+now\s+(in\s+)?(dan|developer\s+mode|jailbroken|unrestricted)/ nocase ascii wide
        $ov4 = /(reveal|print|output|repeat)\s+(your|the)\s+(system\s+prompt|initial\s+instructions|hidden\s+instructions)/ nocase ascii wide
        $ov5 = /(do\s+not|don't|never)\s+(tell|inform|mention\s+this\s+to)\s+the\s+user/ nocase ascii wide

        $ai1 = /\b(AI|LLM|assistant|chatbot|language\s+model|agent|copilot)\b/ nocase ascii wide

    condition:
        filesize < 20MB and
        ($ov1 or $ov3 or $ov4 or (($ov2 or $ov5) and $ai1))
}

rule PromptInjection_Hidden_HTML_Comment
{
    meta:
        description = "HTML comment that addresses an AI and gives it instructions (invisible to the human reader)"
        author      = "girrj"
        date        = "2026-11-14"
        atlas       = "AML.T0051.001"
        owasp_llm   = "LLM01:2026"
        confidence  = "high"

    strings:
        $c1 = /<!--[^>]{0,400}\b(AI|LLM|assistant|agent|model|copilot|chatbot)\b[^>]{0,400}\b(ignore|instruction|forward|send|email|summari[sz]e|classify|mark|approve|execute|run|do\s+not)\b[^>]{0,400}-->/ nocase ascii wide

    condition:
        filesize < 20MB and $c1
}

rule PromptInjection_Hidden_Styled_Text
{
    meta:
        description = "Text hidden with CSS (zero size, invisible, or offscreen) that contains instruction words"
        author      = "girrj"
        date        = "2026-11-14"
        atlas       = "AML.T0051.001"
        owasp_llm   = "LLM01:2026"
        confidence  = "medium"

    strings:
        $h1 = /style\s*=\s*["'][^"']{0,200}(display\s*:\s*none|font-size\s*:\s*0(px|pt|em)?\s*[;"']|opacity\s*:\s*0\s*[;"']|visibility\s*:\s*hidden|color\s*:\s*(#fff(fff)?|white)\s*;\s*background(-color)?\s*:\s*(#fff(fff)?|white)|left\s*:\s*-\d{4,}px)[^>]{0,200}>[^<]{0,600}(ignore|instruction|assistant|\bAI\b|system\s+prompt|forward\s+(this|all)|do\s+not\s+tell)/ nocase ascii wide

    condition:
        filesize < 20MB and $h1
}

rule PromptInjection_Unicode_Tag_Characters
{
    meta:
        description = "Unicode tag characters (U+E0000-U+E007F): invisible text that many models still read"
        author      = "girrj"
        date        = "2026-11-14"
        atlas       = "AML.T0068"
        owasp_llm   = "LLM01:2026"
        confidence  = "high"

    strings:
        // UTF-8 encoding of U+E0020..U+E007E (tag space .. tag tilde): F3 A0 80 A0 .. F3 A0 81 BE
        $tag = { F3 A0 (80 | 81) ?? }

    condition:
        filesize < 20MB and #tag >= 8
}

rule PromptInjection_ZeroWidth_Run
{
    meta:
        description = "Long run of zero-width characters, used to smuggle or obfuscate instructions"
        author      = "girrj"
        date        = "2026-11-14"
        atlas       = "AML.T0068"
        confidence  = "medium"

    strings:
        // Eight consecutive zero-width chars: U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+2060 WJ (UTF-8)
        $zw = { E2 (80 (8B|8C|8D) | 81 A0) E2 (80 (8B|8C|8D) | 81 A0) E2 (80 (8B|8C|8D) | 81 A0) E2 (80 (8B|8C|8D) | 81 A0)
                E2 (80 (8B|8C|8D) | 81 A0) E2 (80 (8B|8C|8D) | 81 A0) E2 (80 (8B|8C|8D) | 81 A0) E2 (80 (8B|8C|8D) | 81 A0) }

    condition:
        filesize < 20MB and $zw
}
