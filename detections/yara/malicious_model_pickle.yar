/*
   Code execution inside Python pickle and pickle-based model files.

   Pickle is the serialization format behind many ML model files (PyTorch
   .pt/.pth/.bin, joblib, older Hugging Face checkpoints). Unpickling runs
   whatever callable the file references, so a "model" downloaded from a hub
   or shared drive can run os.system the moment it is loaded.

   These rules look for references to code-execution callables in the two
   pickle opcode forms (and the Python 2 module names that pickle protocol <= 2
   writes for compatibility):
     - GLOBAL (protocol 0-3):        'c' + "module\nname\n"
     - STACK_GLOBAL (protocol 4-5):   SHORT_BINUNICODE module, SHORT_BINUNICODE
                                      name (optionally MEMOIZE), then 0x93
   PyTorch's zip format stores data.pkl uncompressed, so the same strings
   are visible inside .pt/.pth archives.

   Run these on model files before loading them, alongside a dedicated
   scanner (picklescan, modelscan, fickling). Prefer safetensors for any
   model you distribute.

   MITRE ATLAS: AML.T0010 (AI supply chain compromise), AML.T0011 (user execution).
   OWASP LLM Top 10 2026: LLM04 Supply Chain. OWASP Agentic 2026: ASI04.

   Author: girrj   License: MIT
*/

rule Pickle_CodeExec_Global_Opcode
{
    meta:
        description = "Pickle GLOBAL opcode referencing a code-execution callable (protocol 0-3)"
        author      = "girrj"
        date        = "2026-11-14"
        atlas       = "AML.T0010"
        confidence  = "high"

    strings:
        $g01 = "cos\nsystem\n"
        $g02 = "cposix\nsystem\n"
        $g03 = "cnt\nsystem\n"
        $g04 = "cos\npopen\n"
        $g05 = "cposix\npopen\n"
        $g06 = "cos\nexecv"
        $g07 = "cposix\nexecv"
        $g08 = "csubprocess\nPopen\n"
        $g09 = "csubprocess\nrun\n"
        $g10 = "csubprocess\ncall\n"
        $g11 = "csubprocess\ncheck_output\n"
        $g12 = "csubprocess\ngetoutput\n"
        $g13 = "cbuiltins\neval\n"
        $g14 = "cbuiltins\nexec\n"
        $g15 = "cbuiltins\ncompile\n"
        $g16 = "cbuiltins\n__import__\n"
        $g17 = "c__builtin__\neval\n"
        $g18 = "c__builtin__\nexecfile\n"
        $g19 = "c__builtin__\n__import__\n"
        $g20 = "cruntime\nexec"
        $g21 = "cpty\nspawn\n"
        $g22 = "csocket\nsocket\n"
        $g23 = "cwebbrowser\nopen"
        // Protocol <= 2 with fix_imports (the default) rewrites module names to
        // their Python 2 equivalents: subprocess -> commands, builtins -> __builtin__.
        $g24 = "ccommands\nPopen\n"
        $g25 = "ccommands\ngetoutput\n"
        $g26 = "ccommands\ngetstatusoutput\n"
        $g27 = "c__builtin__\nexec\n"
        $g28 = "c__builtin__\ncompile\n"

    condition:
        filesize < 2048MB and any of them
}

rule Pickle_CodeExec_StackGlobal_Opcode
{
    meta:
        description = "Pickle STACK_GLOBAL referencing a code-execution callable (protocol 4-5)"
        author      = "girrj"
        date        = "2026-11-14"
        atlas       = "AML.T0010"
        confidence  = "high"

    strings:
        // 8C <len> module [94] 8C <len> name [94] 93
        $os_system      = { 8C 02 6F 73 [0-1] 8C 06 73 79 73 74 65 6D [0-1] 93 }                    // os system
        $posix_system   = { 8C 05 70 6F 73 69 78 [0-1] 8C 06 73 79 73 74 65 6D [0-1] 93 }          // posix system
        $nt_system      = { 8C 02 6E 74 [0-1] 8C 06 73 79 73 74 65 6D [0-1] 93 }                    // nt system
        $os_popen       = { 8C (02 6F 73 | 05 70 6F 73 69 78) [0-1] 8C 05 70 6F 70 65 6E [0-1] 93 } // os|posix popen
        $sp_popen       = { 8C 0A 73 75 62 70 72 6F 63 65 73 73 [0-1] 8C 05 50 6F 70 65 6E [0-1] 93 } // subprocess Popen
        $sp_run         = { 8C 0A 73 75 62 70 72 6F 63 65 73 73 [0-1] 8C (03 72 75 6E | 04 63 61 6C 6C | 0C 63 68 65 63 6B 5F 6F 75 74 70 75 74 | 09 67 65 74 6F 75 74 70 75 74) [0-1] 93 }
        $bi_eval        = { 8C 08 62 75 69 6C 74 69 6E 73 [0-1] 8C (04 65 76 61 6C | 04 65 78 65 63 | 07 63 6F 6D 70 69 6C 65 | 0A 5F 5F 69 6D 70 6F 72 74 5F 5F) [0-1] 93 }

    condition:
        filesize < 2048MB and any of them
}

rule Pickle_Embedded_In_Model_Archive_With_Exec
{
    meta:
        description = "Zip-based model archive (e.g. PyTorch .pt) whose embedded data.pkl references code execution"
        author      = "girrj"
        date        = "2026-11-14"
        atlas       = "AML.T0010"
        confidence  = "high"

    strings:
        $pkl  = "data.pkl"
        $e0   = "commands\nPopen"
        $e1   = "posix\nsystem"
        $e2   = "os\nsystem"
        $e3   = "subprocess"
        $e4   = "builtins\neval"
        $e5   = "builtins\nexec"
        $e6   = { 8C 06 73 79 73 74 65 6D [0-1] 93 }     // "system" + STACK_GLOBAL
        $e7   = { 8C 04 65 76 61 6C [0-1] 93 }           // "eval" + STACK_GLOBAL

    condition:
        uint32(0) == 0x04034B50 and $pkl and any of ($e*)
}
