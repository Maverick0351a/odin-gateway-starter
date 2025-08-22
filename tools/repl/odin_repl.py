
import os, sys, subprocess, json
from pathlib import Path
from openai import OpenAI

BANNER = "ODIN Terminal REPL - build assistant\nType /help for commands. Ctrl+C to exit.\n"

WORKSPACE = Path(__file__).resolve().parents[2]  # repo root
TRANSCRIPT = []
MODEL = os.environ.get("OPENAI_MODEL", "gpt-5")
SYSTEM = "You are ODIN build copilot. Be terse, accurate, propose unified diffs when editing files."

client = None
def ensure_client():
    global client
    if client is None:
        key = os.environ.get("OPENAI_API_KEY")
        if not key:
            print("ERROR: OPENAI_API_KEY is not set. Export it and restart the REPL.")
            return None
        client = OpenAI(api_key=key)
    return client

def add_transcript(role, content):
    TRANSCRIPT.append({"role": role, "content": content})

def help_text():
    return (
        "Commands:\n"
        "  /help                         Show this help\n"
        "  /model <name>                 Set model (e.g., gpt-5)\n"
        "  /system <text>                Set system prompt\n"
        "  /open <path>                  Print a file relative to repo root\n"
        "  /ask <text>                   Ask a question (uses current model)\n"
        "  /edit <path> :: <instruction> Ask the model to rewrite the file with the instruction; writes back\n"
        "  /run \"<shell command>\"        Run a shell command in repo root and print output\n"
        "  /save <path>                  Save transcript to file\n"
        "  /cwd                          Print repo root\n"
    )

def read_file(path_str):
    path = (WORKSPACE / path_str).resolve()
    if not str(path).startswith(str(WORKSPACE)):
        raise ValueError("Path escapes workspace")
    if not path.exists():
        raise FileNotFoundError(path_str)
    return path.read_text(encoding="utf-8")

def write_file(path_str, content):
    path = (WORKSPACE / path_str).resolve()
    if not str(path).startswith(str(WORKSPACE)):
        raise ValueError("Path escapes workspace")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

def ask_model(prompt, extra_context=None, stream=True):
    c = ensure_client()
    if not c:
        return None
    parts = []
    if SYSTEM:
        parts.append(f"[SYSTEM]\n{SYSTEM}")
    if extra_context:
        parts.append(f"[CONTEXT]\n{extra_context}")
    parts.append(f"[PROMPT]\n{prompt}")
    full = "\n\n".join(parts)

    if stream:
        with c.responses.stream(model=MODEL, input=full, temperature=0.2) as stream_obj:
            add_transcript("user", full)
            out = []
            for event in stream_obj:
                if event.type == "response.output_text.delta":
                    sys.stdout.write(event.delta)
                    sys.stdout.flush()
                    out.append(event.delta)
            print()
            text = "".join(out)
            add_transcript("assistant", text)
            return text
    else:
        resp = c.responses.create(model=MODEL, input=full, temperature=0.2)
        text = resp.output_text
        print(text)
        add_transcript("user", full)
        add_transcript("assistant", text)
        return text

def extract_code_block(text):
    import re
    m = re.search(r"```(?:[a-zA-Z0-9_+-]+)?\n([\s\S]*?)```", text)
    if m:
        return m.group(1)
    return None

def run_shell(cmd):
    print(f"$ {cmd}")
    try:
        p = subprocess.Popen(cmd, cwd=str(WORKSPACE), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        out_lines = []
        for line in iter(p.stdout.readline, ''):
            print(line, end="")
            out_lines.append(line)
        p.wait()
        return "".join(out_lines)
    except Exception as e:
        print(f"[shell error] {e}")
        return ""

def main():
    print(BANNER)
    print(f"Workspace: {WORKSPACE}")
    print(f"Model: {MODEL}")
    while True:
        try:
            line = input("> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nBye.")
            break
        if not line:
            continue
        if line == "/help":
            print(help_text()); continue
        if line.startswith("/cwd"):
            print(WORKSPACE); continue
        if line.startswith("/model "):
            global MODEL
            MODEL = line.split(" ",1)[1].strip()
            print(f"Model set to {MODEL}")
            continue
        if line.startswith("/system "):
            global SYSTEM
            SYSTEM = line.split(" ",1)[1].strip()
            print("System prompt updated.")
            continue
        if line.startswith("/open "):
            path = line.split(" ",1)[1].strip()
            try:
                content = read_file(path)
                print(f"--- {path} ---")
                print(content)
            except Exception as e:
                print(f"[open error] {e}")
            continue
        if line.startswith("/ask "):
            prompt = line.split(" ",1)[1].strip()
            ask_model(prompt, extra_context=None, stream=True)
            continue
        if line.startswith("/edit "):
            try:
                rest = line.split(" ",1)[1]
                if "::" in rest:
                    path, instruction = [p.strip() for p in rest.split("::",1)]
                else:
                    path = rest.strip()
                    instruction = input("Edit instruction: ").strip()
                original = read_file(path)
                prompt = f"You are editing the file {path}. Apply this instruction:\n{instruction}\n\nReturn ONLY the full updated file content in a single fenced code block."
                reply = ask_model(prompt, extra_context=original, stream=False)
                new_content = extract_code_block(reply) or reply
                write_file(path, new_content)
                print(f"[edit] Wrote updated file: {path}")
            except Exception as e:
                print(f"[edit error] {e}")
            continue
        if line.startswith("/run "):
            cmd = line.split(" ",1)[1].strip().strip('"')
            run_shell(cmd)
            continue
        if line.startswith("/save "):
            path = line.split(" ",1)[1].strip()
            try:
                p = (WORKSPACE / path).resolve()
                if not str(p).startswith(str(WORKSPACE)):
                    raise ValueError("Path escapes workspace")
                with p.open("w", encoding="utf-8") as f:
                    json.dump(TRANSCRIPT, f, indent=2)
                print(f"[save] wrote {p}")
            except Exception as e:
                print(f"[save error] {e}")
            continue
        # default: treat as ask
        ask_model(line, stream=True)

if __name__ == "__main__":
    main()
