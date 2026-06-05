import json
import os
import html
from datetime import datetime
from utils.output import section, info, success, warning, error


class ReportGen:
    description = "Generate HTML/JSON penetration testing reports from JSON output files"

    @staticmethod
    def run(input="", output="", format="html", title="", author="", **kwargs):
        section("Report Generator")

        if not input:
            error("No input file(s) provided (use --input)")
            return {"error": "no input"}

        files = [f.strip() for f in input.split(",") if f.strip()]

        all_results = {}
        for f in files:
            if not os.path.exists(f):
                warning(f"File not found: {f}")
                continue
            try:
                with open(f) as fh:
                    all_results[os.path.basename(f)] = json.load(fh)
                info(f"Loaded {f}")
            except:
                warning(f"Cannot parse {f}")

        if not all_results:
            error("No valid result files to process")
            return {"error": "no valid files"}

        target = kwargs.get("target", kwargs.get("domain", ""))
        if not target:
            import re
            for k in all_results:
                data = all_results[k]
                if isinstance(data, dict):
                    for t_key in ("target", "domain", "url", "host"):
                        if t_key in data and isinstance(data[t_key], str):
                            target = data[t_key]
                            break
                if target:
                    break

        report_title = title or f"Security Assessment: {target or 'Unknown Target'}"
        report_author = author or "Reconnor Security Tool"

        result_data = {
            "title": report_title,
            "author": report_author,
            "date": datetime.now().isoformat(),
            "target": target,
            "files_processed": files,
            "results": all_results,
        }

        if format == "html":
            html_output = ReportGen._generate_html(all_results, report_title, report_author, target)
            if output:
                with open(output, "w") as f:
                    f.write(html_output)
                success(f"HTML report written to {output}")
            else:
                out_file = "reconnor_report.html"
                with open(out_file, "w") as f:
                    f.write(html_output)
                success(f"HTML report written to {out_file}")
                output = out_file
        elif format == "json":
            if output:
                with open(output, "w") as f:
                    json.dump(result_data, f, indent=2, default=str)
            else:
                output = "reconnor_report.json"
                with open(output, "w") as f:
                    json.dump(result_data, f, indent=2, default=str)
            success(f"JSON report written to {output}")
        elif format == "txt":
            txt = ReportGen._generate_txt(all_results, report_title, target)
            if output:
                with open(output, "w") as f:
                    f.write(txt)
            else:
                output = "reconnor_report.txt"
                with open(output, "w") as f:
                    f.write(txt)
            success(f"Text report written to {output}")
        else:
            error(f"Unknown format: {format} (use html, json, or txt)")
            return {"error": f"unknown format: {format}"}

        result_data["output_file"] = output
        return result_data

    @staticmethod
    def _generate_html(all_results, title, author, target):
        css = """
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f0f1a; color: #e0e0e0; line-height: 1.6; padding: 20px; }
          .container { max-width: 1200px; margin: 0 auto; }
          h1 { color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; margin-bottom: 20px; }
          h2 { color: #ffa500; margin: 25px 0 10px; }
          h3 { color: #00d4ff; margin: 15px 0 8px; }
          .meta { color: #888; font-size: 14px; margin-bottom: 20px; }
          .summary { background: #1a1a2e; border-left: 4px solid #00d4ff; padding: 15px; margin: 15px 0; border-radius: 4px; }
          .finding { background: #1a1a2e; border: 1px solid #2a2a4e; padding: 12px; margin: 8px 0; border-radius: 4px; }
          .finding.critical { border-left: 4px solid #ff4444; }
          .finding.high { border-left: 4px solid #ff8800; }
          .finding.medium { border-left: 4px solid #ffcc00; }
          .finding.low { border-left: 4px solid #00cc88; }
          table { width: 100%; border-collapse: collapse; margin: 12px 0; }
          th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #2a2a4e; }
          th { background: #1a1a2e; color: #00d4ff; }
          pre { background: #0a0a15; padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 13px; }
          .tag { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 12px; margin: 2px; }
          .tag.critical { background: #ff4444; color: white; }
          .tag.high { background: #ff8800; color: white; }
          .tag.medium { background: #ffcc00; color: black; }
          .tag.low { background: #00cc88; color: white; }
        </style>
        """

        summary_items = []
        data_json = {}

        for fname, data in all_results.items():
            if isinstance(data, dict):
                if "vulnerable" in data and isinstance(data["vulnerable"], list):
                    summary_items.append(f'<p><strong>{fname}:</strong> {len(data["vulnerable"])} vulnerability/ies found</p>')
                if "found" in data and isinstance(data["found"], list):
                    summary_items.append(f'<p><strong>{fname}:</strong> {len(data["found"])} findings</p>')
                if "open_ports" in data and isinstance(data["open_ports"], list):
                    summary_items.append(f'<p><strong>{fname}:</strong> {len(data["open_ports"])} open ports</p>')
                if "subdomains" in data and isinstance(data["subdomains"], list):
                    summary_items.append(f'<p><strong>{fname}:</strong> {len(data["subdomains"])} subdomains</p>')
                if "emails" in data and isinstance(data["emails"], list):
                    summary_items.append(f'<p><strong>{fname}:</strong> {len(data["emails"])} emails</p>')
            data_json[fname] = data

        summary_html = "\n".join(summary_items) if summary_items else "<p>No structured findings summary available.</p>"

        details_html = ""
        for fname, data in all_results.items():
            details_html += f'<div class="finding"><h3>{html.escape(fname)}</h3>'
            details_html += f"<pre>{html.escape(json.dumps(data, indent=2, default=str))}</pre></div>"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{html.escape(title)}</title>
  {css}
</head>
<body>
<div class="container">
  <h1>{html.escape(title)}</h1>
  <div class="meta">
    <p><strong>Target:</strong> {html.escape(target or 'N/A')}</p>
    <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
    <p><strong>Author:</strong> {html.escape(author)}</p>
  </div>

  <h2>Executive Summary</h2>
  <div class="summary">{summary_html}</div>

  <h2>Detailed Findings</h2>
  {details_html}
</div>
</body>
</html>"""
        return html_content

    @staticmethod
    def _generate_txt(all_results, title, target):
        lines = []
        lines.append("=" * 70)
        lines.append(f"  {title}")
        lines.append("=" * 70)
        lines.append(f"Target: {target or 'N/A'}")
        lines.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        lines.append("")

        for fname, data in all_results.items():
            lines.append("-" * 50)
            lines.append(f"  {fname}")
            lines.append("-" * 50)
            lines.append(json.dumps(data, indent=2, default=str))
            lines.append("")

        return "\n".join(lines)
