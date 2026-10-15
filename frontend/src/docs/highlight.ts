import hljs from "highlight.js/lib/core";
import bash from "highlight.js/lib/languages/bash";
import dockerfile from "highlight.js/lib/languages/dockerfile";
import http from "highlight.js/lib/languages/http";
import ini from "highlight.js/lib/languages/ini";
import json from "highlight.js/lib/languages/json";
import makefile from "highlight.js/lib/languages/makefile";
import python from "highlight.js/lib/languages/python";
import typescript from "highlight.js/lib/languages/typescript";
import yaml from "highlight.js/lib/languages/yaml";
import type { HLJSApi, Language } from "highlight.js";

/** Minimal Cypher grammar (FalkorDB's query language), enough for the snippets in the docs. */
function cypher(h: HLJSApi): Language {
  return {
    name: "Cypher",
    case_insensitive: true,
    keywords: {
      keyword:
        "match optional where return with unwind call yield order by limit skip as and or not " +
        "in is null distinct create merge set delete detach remove case when then else end " +
        "asc desc exists all any none single",
      literal: "true false null",
      built_in: "coalesce size nodes relationships length collect count id labels type",
    },
    contains: [
      h.QUOTE_STRING_MODE,
      h.APOS_STRING_MODE,
      h.C_LINE_COMMENT_MODE,
      h.C_NUMBER_MODE,
      { className: "variable", begin: /\$[A-Za-z_]\w*/ },
      { className: "type", begin: /:[A-Za-z_][\w]*/ },
    ],
  };
}

hljs.registerLanguage("bash", bash);
hljs.registerLanguage("dockerfile", dockerfile);
hljs.registerLanguage("http", http);
hljs.registerLanguage("ini", ini);
hljs.registerLanguage("json", json);
hljs.registerLanguage("makefile", makefile);
hljs.registerLanguage("python", python);
hljs.registerLanguage("typescript", typescript);
hljs.registerLanguage("yaml", yaml);
hljs.registerLanguage("cypher", cypher);
hljs.registerAliases(["sh", "shell", "console"], { languageName: "bash" });
hljs.registerAliases(["env", "dotenv"], { languageName: "ini" });
hljs.registerAliases(["py"], { languageName: "python" });
hljs.registerAliases(["ts", "tsx"], { languageName: "typescript" });
hljs.registerAliases(["yml"], { languageName: "yaml" });

const ESC: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" };

/** Highlighted HTML for a code block; unknown languages are escaped as plain text. */
export function highlight(code: string, lang: string): string {
  if (lang && hljs.getLanguage(lang)) return hljs.highlight(code, { language: lang }).value;
  return code.replace(/[&<>"]/g, (c) => ESC[c]);
}
