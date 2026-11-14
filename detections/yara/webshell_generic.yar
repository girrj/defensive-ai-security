/*
   Generic web shell detection for JSP, ASPX, and PHP.

   Each rule needs BOTH a way to read attacker input from the HTTP request AND
   a way to run it (process execution or dynamic evaluation). Requiring both
   keeps false positives on normal application code low. Run these over web
   roots and upload directories, and over files recovered during an incident.

   Author:  girrj
   Date:    2026-11-14
   License: MIT
*/

rule WebShell_JSP_Generic
{
    meta:
        description  = "JSP that passes request input to process execution or reflection"
        author       = "girrj"
        date         = "2026-11-14"
        mitre_attack = "T1505.003"

    strings:
        $in1   = "request.getParameter" ascii
        $in2   = "request.getHeader" ascii
        $in3   = "request.getInputStream" ascii

        $exec1 = "Runtime.getRuntime().exec" ascii
        $exec2 = "new ProcessBuilder" ascii
        $exec3 = "defineClass" ascii
        $exec4 = "javax.script.ScriptEngineManager" ascii

        $jsp1  = "<%@" ascii
        $jsp2  = "<%" ascii

    condition:
        filesize < 500KB and
        1 of ($jsp*) and
        1 of ($in*) and
        1 of ($exec*)
}

rule WebShell_ASPX_Generic
{
    meta:
        description  = "ASPX that passes request input to process execution or dynamic compilation"
        author       = "girrj"
        date         = "2026-11-14"
        mitre_attack = "T1505.003"

    strings:
        $in1   = "Request.Form" ascii nocase
        $in2   = "Request.QueryString" ascii nocase
        $in3   = "Request.Headers" ascii nocase
        $in4   = "Request.Item" ascii nocase
        $in5   = "Request[" ascii nocase

        $exec1 = "System.Diagnostics.Process" ascii nocase
        $exec2 = "ProcessStartInfo" ascii nocase
        $exec3 = "Assembly.Load" ascii nocase
        $exec4 = "CSharpCodeProvider" ascii nocase
        $exec5 = "eval(" ascii nocase

        $asp   = "<%@ Page" ascii nocase

    condition:
        filesize < 500KB and
        $asp and
        1 of ($in*) and
        1 of ($exec*)
}

rule WebShell_PHP_Generic
{
    meta:
        description  = "PHP that passes superglobal input to command execution or eval"
        author       = "girrj"
        date         = "2026-11-14"
        mitre_attack = "T1505.003"

    strings:
        $php   = "<?php" ascii nocase

        $exec_in = /(system|shell_exec|passthru|exec|popen|proc_open|assert|eval)\s*\(\s*(base64_decode\s*\(\s*)?\$_(GET|POST|REQUEST|COOKIE|SERVER)/ nocase
        $cb_in   = /(call_user_func|create_function|preg_replace)\s*\([^;]{0,80}\$_(GET|POST|REQUEST|COOKIE)/ nocase

    condition:
        filesize < 500KB and
        $php and
        ($exec_in or $cb_in)
}
