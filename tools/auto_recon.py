import json
import sys
import inspect
from utils.output import section, info, success, warning, error
from utils.llm_helper import LLMHelper

TOOL_CHAIN = [
    "subdomain",
    "dns",
    "whois",
    "certsearch",
    "port-scan",
    "tech",
    "waf",
    "crawl",
    "js",
    "forms",
    "ssl",
    "headers",
]

LIGHT_TOOL_CHAIN = [
    "subdomain",
    "dns",
    "whois",
    "port-scan",
    "tech",
    "waf",
    "ssl",
    "headers",
]


class AutoRecon:
    description = "Autonomous reconnaissance orchestrator with AI-driven decision making"

    @staticmethod
    def run(target, use_ai=False, llm_provider="", llm_model="", light=False, threads=50, timeout=10, ext=False, nmap=False, **kwargs):
        section(f"AutoRecon: {target}")
        info("Initializing reconnaissance pipeline")

        kwargs_dict = {
            "threads": threads,
            "timeout": timeout,
            "ext": ext,
            "nmap": nmap,
        }

        if "host" in kwargs:
            kwargs_dict["host"] = kwargs["host"]

        llm = None
        if use_ai:
            llm = LLMHelper(model=llm_model, provider=llm_provider)
            if not llm.available:
                warning(f"LLM provider '{llm.provider}' not available. Running without AI guidance.")

        chain = LIGHT_TOOL_CHAIN if light else TOOL_CHAIN
        results = {}
        step = 1

        for tool_name in chain:
            info(f"[{step}/{len(chain)}] Running {tool_name}...")
            try:
                tool_module = AutoRecon._import_tool(tool_name)
                if tool_module:
                    sig = inspect.signature(tool_module.run)
                    valid_kwargs = {k: v for k, v in kwargs_dict.items() if k in sig.parameters}
                    valid_kwargs["target"] = target
                    result = tool_module.run(**valid_kwargs)
                    results[tool_name] = result
                    success(f"{tool_name} completed")

                    if llm and llm.available:
                        summary = llm.summarize_findings(tool_name, target, result)
                        if summary:
                            info(f"AI summary: {summary[:200]}...")
                            suggestions = llm.suggest_next_steps(
                                target,
                                list(results.keys()),
                                json.dumps(result, default=str)[:1000],
                            )
                            if suggestions and isinstance(suggestions, list):
                                info(f"AI suggests: {', '.join(suggestions[:3])}")
                else:
                    warning(f"Cannot import {tool_name}, skipping")
            except Exception as e:
                error(f"{tool_name} failed: {e}")

            step += 1

        section("Recon Complete")
        success(f"Ran {len(chain)} tools against {target}")

        if llm and llm.available:
            summary = llm.generate_report(target, results)
            if summary:
                section("AI-Generated Engagement Summary")
                print(summary)

        return results

    @staticmethod
    def _import_tool(name):
        from tools import TOOLS as tool_registry
        return tool_registry.get(name)
