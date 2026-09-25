import ast
import hashlib
import os
import json
import sys

class PromptASTScanner(ast.NodeVisitor):
    def __init__(self, filepath):
        self.filepath = filepath
        self.found_prompts = []
        self.assignments = {}  # Tracks variable assignments (e.g., system_prompt = "...")

    def visit_Assign(self, node):
        """Track variable declarations so we can resolve variable references later."""
        # Check if the target is a simple variable name
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id
            # If it's assigned a string literal
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                self.assignments[var_name] = {
                    "text": node.value.value,
                    "line": node.lineno
                }
        self.generic_visit(node)

    def visit_Call(self, node):
        """Scan function calls for OpenAI, Anthropic, or Gemini system prompt patterns."""
        # 1. Look for Anthropic or Gemini style keyword arguments (system=..., system_instruction=...)
        for keyword in node.keywords:
            if keyword.arg in ["system", "system_instruction"]:
                # Case A: Direct string literal inside call
                if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                    self._add_finding(
                        line=node.lineno,
                        api_type="Anthropic/Gemini SDK" if keyword.arg == "system" else "Gemini SDK",
                        pattern=f"keyword: {keyword.arg}",
                        confidence="HIGH",
                        prompt_text=keyword.value.value
                    )
                # Case B: Variable reference used in call (e.g., system=system_prompt)
                elif isinstance(keyword.value, ast.Name) and keyword.value.id in self.assignments:
                    var_name = keyword.value.id
                    self._add_finding(
                        line=node.lineno,
                        api_type="Anthropic/Gemini SDK",
                        pattern=f"keyword: {keyword.arg} (via variable '{var_name}')",
                        confidence="HIGH",
                        prompt_text=self.assignments[var_name]["text"]
                    )

        # 2. Look for OpenAI style messages=[{"role": "system", "content": "..."}]
        for keyword in node.keywords:
            if keyword.arg == "messages" and isinstance(keyword.value, ast.List):
                for element in keyword.value.elts:
                    if isinstance(element, ast.Dict):
                        # Extract keys and values from the dictionary element
                        keys = [k.value for k in element.keys if isinstance(k, ast.Constant)]
                        
                        # Look for 'role' mapping to 'system'
                        role_val = None
                        content_val = None
                        content_node = None

                        for k, v in zip(element.keys, element.values):
                            if isinstance(k, ast.Constant):
                                if k.value == "role" and isinstance(v, ast.Constant) and v.value == "system":
                                    role_val = "system"
                                if k.value == "content":
                                    content_node = v

                        if role_val == "system" and content_node:
                            # Direct string literal
                            if isinstance(content_node, ast.Constant) and isinstance(content_node.value, str):
                                self._add_finding(
                                    line=node.lineno,
                                    api_type="OpenAI SDK",
                                    pattern="messages array containing system role",
                                    confidence="HIGH",
                                    prompt_text=content_node.value
                                )
                            # Resolved Variable reference
                            elif isinstance(content_node, ast.Name) and content_node.id in self.assignments:
                                var_name = content_node.id
                                self._add_finding(
                                    line=node.lineno,
                                    api_type="OpenAI SDK",
                                    pattern=f"messages array via variable '{var_name}'",
                                    confidence="HIGH",
                                    prompt_text=self.assignments[var_name]["text"]
                                )

        self.generic_visit(node)

    def _add_finding(self, line, api_type, pattern, confidence, prompt_text):
        self.found_prompts.append({
            "file": os.path.normpath(self.filepath),
            "line": line,
            "api_type": api_type,
            "pattern": pattern,
            "confidence": confidence,
            "prompt_length": len(prompt_text),
            "prompt_hash": hashlib.sha256(prompt_text.strip().encode("utf-8")).hexdigest(),
            "system_prompt": prompt_text.strip()
        })

def scan_directory(target_dir):
    """Walks the target directory, skipping standard exclusions, and processes Python files."""
    skip_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv", "env", "dist", "build"}
    all_findings = []

    if not os.path.exists(target_dir):
        print(f"Error: Target directory '{target_dir}' does not exist.")
        sys.exit(1)

    for root, dirs, files in os.walk(target_dir):
        # Filter out directories to skip in-place
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        
        for file in files:
            if file.endswith(".py"):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        source_code = f.read()
                    
                    tree = ast.parse(source_code, filename=filepath)
                    scanner = PromptASTScanner(filepath)
                    scanner.visit(tree)
                    all_findings.extend(scanner.found_prompts)
                except Exception as e:
                    print(f"Failed parsing {filepath}: {str(e)}")

    # Write output to the reports directory
    os.makedirs("reports", exist_ok=True)
    output_path = "reports/system_prompts.json"
    
    with open(output_path, "w", encoding="utf-8") as out_f:
        json.dump(all_findings, out_f, indent=2)

    print(f"\nSuccessfully scanned directory: {target_dir}")
    print(f"Extracted system prompts count: {len(all_findings)}")
    print(f"Results saved securely to: {output_path}")

if __name__ == "__main__":
    # Allow passing directory via argument, default to test_targets/
    target = sys.argv[1] if len(sys.argv) > 1 else "test_targets/"
    scan_directory(target)